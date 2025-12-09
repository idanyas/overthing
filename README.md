# Tunnel

A Go library for creating secure, multiplexed, NAT-traversing TCP tunnels using the Syncthing relay network.

This package allows you to connect two endpoints (behind NATs or firewalls) by using Syncthing's global relay network as a rendezvous point. Once connected, the connection is upgraded to a direct TLS 1.3 tunnel with stream multiplexing via [yamux](https://github.com/hashicorp/yamux).

## Features

- **NAT Traversal**: Connect endpoints behind restrictive firewalls without port forwarding.
- **End-to-End Encryption**: All traffic is wrapped in TLS 1.3. Relays simply forward encrypted bytes and cannot see the content.
- **Connection Multiplexing**: Run multiple logical streams over a single relay connection.
- **Authentication**: Uses Ed25519-based identities and Device IDs (compatible with Syncthing).
- **Automatic Reconnection**: Clients automatically reconnect if the tunnel drops.
- **Minimal Dependencies**: Pure Go implementation.

## Installation

### As a Library

```bash
go get github.com/yourusername/tunnel
```

*(Note: Replace `github.com/yourusername/tunnel` with your actual module path).*

## Quick Start

The project includes ready-to-run examples in the `examples/` directory.

### 1. Start the Server

The server listens for incoming tunnel connections and forwards them to a local port (e.g., a web server on port 8080).

```bash
# Start a simple web server for testing (optional)
# python3 -m http.server 8080 &

# Start the tunnel server
# It will generate a 'server.key' identity file on first run.
go run examples/server/main.go
```

**Output:**
```text
INFO  Loaded identity from ./server.key
INFO  Server Device ID: <SERVER-DEVICE-ID>
INFO  Full Device ID: <FULL-SERVER-DEVICE-ID>
INFO  Waiting for connections...
```

Copy the **Server Device ID** (the short or full one). You will need it for the client.

### 2. Start the Client

The client connects to the server via the relay and exposes the service on a local port.

```bash
# Connect to the server and listen on local port 9000
# Replace <SERVER-DEVICE-ID> with the ID from the server output
go run examples/client/main.go <SERVER-DEVICE-ID>
```

**Output:**
```text
INFO  Client Device ID: <CLIENT-DEVICE-ID>
INFO  Listening on 127.0.0.1:9000
OK    Tunnel established (multiplexed)
```

### 3. Connect

Now you can connect to the client's local port to reach the service on the server side.

```bash
curl http://127.0.0.1:9000
```

## Library Usage

### Creating a Server

```go
package main

import (
    "context"
    "tunnel"
)

func main() {
    // 1. Load identity
    identity, _ := tunnel.LoadOrGenerateIdentity("./server.key")

    // 2. Configure server
    cfg := tunnel.ServerConfig{
        Identity:    identity,
        ForwardAddr: "127.0.0.1:8080", // Target service
        
        // Optional: Restrict access to specific client Device IDs
        AllowedClientIDs: []string{
            "CLIENT-DEVICE-ID-1",
        },
        
        // Callbacks
        OnConnect: func(id string) { println("Client connected:", id) },
    }

    // 3. Start server
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
    // 1. Load identity
    identity, _ := tunnel.LoadOrGenerateIdentity("./client.key")

    // 2. Configure client
    cfg := tunnel.ClientConfig{
        Identity:   identity,
        TargetID:   "SERVER-DEVICE-ID", // The server we want to reach
        ListenAddr: "127.0.0.1:2222",   // Local listener
    }

    // 3. Start client
    client, _ := tunnel.NewClient(cfg)
    client.Run(context.Background())
}
```

### One-Shot Dialing

If you don't need a listener and just want a `net.Conn` to the remote server:

```go
conn, err := tunnel.Dial(tunnel.ClientConfig{
    Identity: identity,
    TargetID: "SERVER-DEVICE-ID",
})
```

## Configuration

### ServerConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Identity` | `Identity` | **Required** | The server's crypto identity. |
| `ForwardAddr` | `string` | `127.0.0.1:22` | Local address to forward traffic to. |
| `RelayURI` | `string` | Syncthing Default | URI of the relay server. |
| `AllowedClientIDs` | `[]string` | `nil` | List of allowed client Device IDs. |
| `AllowAnyClient` | `bool` | `false` | Explicitly allow all clients (ignores list). |
| `ReconnectDelay` | `Duration` | `500ms` | Wait time before retrying relay connection. |
| `OnConnect` | `func(string)` | `nil` | Callback when a client connects. |
| `OnDisconnect` | `func(string)` | `nil` | Callback when a client disconnects. |
| `Logger` | `func` | `nil` | Custom logger function. |

**Security Note:** If `AllowedClientIDs` is empty and `AllowAnyClient` is false, the server defaults to allowing **ALL** connections for backward compatibility. To restrict access, you must populate `AllowedClientIDs`.

### ClientConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Identity` | `Identity` | **Required** | The client's crypto identity. |
| `TargetID` | `string` | **Required** | Device ID of the server. |
| `ListenAddr` | `string` | `127.0.0.1:2222` | Local TCP address to listen on. |
| `RelayURI` | `string` | Syncthing Default | URI of the relay server. |
| `ReconnectDelay` | `Duration` | `500ms` | Wait time before retrying connection. |

## Identities & Device IDs

This library uses the same identity format as Syncthing (Ed25519).

- **Identity File**: Contains the 32-byte Ed25519 seed, encoded as a 43-character Base64URL string.
- **Device ID (Full)**: 56 characters, Base32 encoded with Luhn check digits.
- **Device ID (Compact)**: 43 characters, Base64URL encoded SHA-256 hash of the certificate.

Both ID formats are supported for `TargetID` and `AllowedClientIDs`.

## Architecture

1. **Relay Connection**: Both Client and Server connect to a public Syncthing relay via TCP/TLS.
2. **Session Request**: Client asks Relay to connect to Server's Device ID.
3. **Invitation**: Relay notifies Server. Server accepts.
4. **P2P Tunnel**: Relay bridges the bytes. Client and Server perform a TLS 1.3 handshake *through* the relay.
    - This ensures the Relay cannot read the traffic (End-to-End Encryption).
    - Authentication is mutual based on Device IDs (derived from TLS certificates).
5. **Multiplexing**: A `yamux` session is established inside the TLS tunnel.
6. **Data Transfer**: When a connection is made to the Client's `ListenAddr`, a new stream is opened in the yamux session, and data is copied to the Server's `ForwardAddr`.

## Custom Relays

To use a private relay or a specific public relay:

```go
config.RelayURI = "relay://1.2.3.4:22067/?id=<RELAY-DEVICE-ID>"
```
