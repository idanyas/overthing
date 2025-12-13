# Tunnel

A Go library for creating secure, multiplexed, NAT-traversing TCP tunnels using the Syncthing relay network.

This package allows you to connect two endpoints (behind NATs or firewalls) by using Syncthing's global relay network as a rendezvous point.

## Features

- **NAT Traversal**: Connect endpoints behind restrictive firewalls without port forwarding.
- **Relay Hints**: Device IDs automatically embed the current relay address, allowing instant direct connections without discovery overhead.
- **Fallback Discovery**: If the embedded relay hint fails (e.g., server switched relays), the client automatically scans the global network to find the device.
- **End-to-End Encryption**: All traffic is wrapped in TLS 1.3. Relays simply forward encrypted bytes and cannot see the content.
- **Connection Multiplexing**: Run multiple logical streams over a single relay connection.

## Installation

```bash
go get github.com/yourusername/tunnel
```

## Quick Start

### 1. Start the Server

```bash
go run examples/server/main.go
```

**Output:**
```text
RELAY TUNNEL SERVER
-------------------
  Device ID: QAV07YUWsUlUEVsxQyHUPHvpKd86w0jaEnkUZPI_WLAAbCdEfGh
  Forward:   127.0.0.1:22
  Identity:  /path/to/server.key

  (ID includes relay hint for direct connection)
```

The Server generates a **Device ID with Hint**. This 51-character string contains:
- **First 43 chars**: The cryptographic identity (Base63 encoded SHA-256 of certificate)
- **Last 8 chars**: The relay IP:Port hint (Base63 encoded)

### 2. Start the Client

Pass the Server's Device ID (with or without hint) to the client.

```bash
# Replace <DEVICE-ID> with the output from the server (all 51 chars!)
go run examples/client/main.go <DEVICE-ID>
```

**Client Connection Logic:**
1. **Extract Hint**: If the ID is 51 chars, extract the embedded relay IP:Port
2. **Direct Connect**: Try to connect to the hinted relay immediately
3. **Fallback**: If that relay fails or doesn't know the server, scan all relays
4. **Connect**: Establish secure tunnel to the server

## Device ID Formats

| Format | Length | Description |
|--------|--------|-------------|
| Compact | 43 chars | Base63 encoded identity only |
| Compact + Hint | 51 chars | Identity + 8-char relay hint |
| Standard | 56 chars | Syncthing-compatible with Luhn checksums |
| Standard + Hint | 66 chars | Standard + 10-char Base32 relay hint |

The library automatically detects and handles all formats.

## Library Usage

### Creating a Server

```go
package main

import (
    "context"
    "tunnel"
)

func main() {
    identity, _ := tunnel.LoadOrGenerateIdentity("./server.key")

    cfg := tunnel.ServerConfig{
        Identity:    identity,
        ForwardAddr: "127.0.0.1:8080", 
        OnRelayJoined: func(relayAddr, deviceIDWithHint string) {
            // deviceIDWithHint is 51 chars (43 + 8 hint)
            fmt.Printf("Share this ID: %s\n", deviceIDWithHint)
        },
    }

    server, _ := tunnel.NewServer(cfg)
    server.Run(context.Background())
}
```

### Creating a Client

```go
package main

import (
    "context"
    "tunnel"
)

func main() {
    identity, _ := tunnel.LoadOrGenerateIdentity("./client.key")

    cfg := tunnel.ClientConfig{
        Identity:   identity,
        TargetID:   "DEVICE-ID-WITH-HINT", // Paste the 51-char ID here
        ListenAddr: "127.0.0.1:2222", 
    }

    // The client will:
    // 1. Extract relay hint from the ID
    // 2. Try direct connection to that relay
    // 3. Fall back to discovery if needed
    client, _ := tunnel.NewClient(cfg)
    client.Run(context.Background())
}
```

## How Relay Hints Work

When a server joins a relay, it learns the relay's IP address and port. This information is encoded into 8 characters using Base63 and appended to the Device ID:

```
┌─────────────────────────────────────────────┬────────┐
│          Device ID (43 chars)               │  Hint  │
│  QAV07YUWsUlUEVsxQyHUPHvpKd86w0jaEnkUZPI_WLA│AbCdEfGh│
└─────────────────────────────────────────────┴────────┘
                                               ↓
                                         Decodes to:
                                         198.211.120.59:22067
```

This allows clients to connect directly without any discovery overhead. If the relay changes or becomes unavailable, the client seamlessly falls back to global discovery.

## Examples

The `examples/` directory contains comprehensive examples demonstrating various use cases:

### Basic Examples

```bash
# Server with verbose output
go run examples/server/main.go -v -stats

# Client with statistics
go run examples/client/main.go -v -stats <device-id>

# One-shot dial
go run examples/dial/main.go <device-id>
```

### Advanced Examples

```bash
# Unix socket forwarding
go run examples/unix-socket/main.go -mode echo &    # Start echo on socket
go run examples/unix-socket/main.go -mode server    # Start tunnel server

# In-memory testing (no network required)
go run examples/memory-pipe/main.go

# Echo server for testing
go run examples/echo-server/main.go -addr 127.0.0.1:9999

# All-in-one bidirectional test
go run examples/bidirectional/main.go

# Show all configuration options
go run examples/advanced/main.go -show-config
```

### Internal Go Networking

The library supports custom `net.Listener` and `net.Conn` implementations for advanced use cases:

```go
// Server: Forward to Unix socket instead of TCP
server := tunnel.NewServer(tunnel.ServerConfig{
    TargetDialer: func() (net.Conn, error) {
        return net.Dial("unix", "/var/run/app.sock")
    },
})

// Client: Listen on Unix socket instead of TCP
listener, _ := net.Listen("unix", "/tmp/tunnel.sock")
client := tunnel.NewClient(tunnel.ClientConfig{
    Listener: listener,
})

// Testing: Use in-memory pipes
serverConn, clientConn := net.Pipe()
// Use serverConn in TargetDialer, clientConn for testing
```
