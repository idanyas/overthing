// Unix socket forwarding example
// Demonstrates forwarding tunnel connections to a Unix socket
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"

	"github.com/idanyas/overthing"
)

func main() {
	mode := flag.String("mode", "", "Mode: 'server' or 'client' or 'echo'")
	socketPath := flag.String("socket", "/tmp/tunnel-test.sock", "Unix socket path")
	keyFile := flag.String("key", "./unix-socket.key", "Identity key file")
	targetID := flag.String("target", "", "Target device ID (client mode)")
	listenAddr := flag.String("listen", "127.0.0.1:2222", "Listen address (client mode)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Unix Socket Tunnel Example

This example demonstrates forwarding tunnel traffic to/from Unix sockets.

USAGE:
    %s -mode echo                    # Start echo server on Unix socket
    %s -mode server                  # Start tunnel server forwarding to socket
    %s -mode client -target <id>     # Start tunnel client

MODES:
    echo     Start an echo server listening on the Unix socket
    server   Start tunnel server that forwards to the Unix socket
    client   Start tunnel client (connect via local TCP)

WORKFLOW:
    Terminal 1: %s -mode echo
    Terminal 2: %s -mode server
    Terminal 3: %s -mode client -target <device-id-from-terminal-2>
    Terminal 4: nc localhost 2222   # Type messages, see echoes

OPTIONS:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if runtime.GOOS == "windows" {
		log.Fatal("Unix sockets are not supported on Windows. Use named pipes instead.")
	}

	switch *mode {
	case "echo":
		runEchoServer(*socketPath)
	case "server":
		runUnixServer(*socketPath, *keyFile)
	case "client":
		if *targetID == "" {
			log.Fatal("Target device ID required for client mode")
		}
		runClient(*targetID, *listenAddr, *keyFile)
	default:
		flag.Usage()
		os.Exit(1)
	}
}

func runEchoServer(socketPath string) {
	// Remove existing socket
	os.Remove(socketPath)

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on Unix socket: %v", err)
	}
	defer listener.Close()
	defer os.Remove(socketPath)

	fmt.Println()
	fmt.Println("UNIX SOCKET ECHO SERVER")
	fmt.Println("───────────────────────────────────────────────")
	fmt.Printf("  Socket: %s\n", socketPath)
	fmt.Println("  Status: Listening for connections...")
	fmt.Println("───────────────────────────────────────────────")
	fmt.Println()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleEchoConn(conn)
	}
}

func handleEchoConn(conn net.Conn) {
	defer conn.Close()
	log.Printf("Echo: New connection from %s", conn.RemoteAddr())

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("Echo: Connection closed: %v", err)
			return
		}

		log.Printf("Echo: Received %d bytes: %q", n, buf[:n])

		// Echo back with prefix
		response := fmt.Sprintf("[ECHO] %s", buf[:n])
		conn.Write([]byte(response))
	}
}

func runUnixServer(socketPath, keyFile string) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity, err := tunnel.LoadOrGenerateIdentity(keyFile)
	if err != nil {
		log.Fatalf("Failed to load identity: %v", err)
	}

	absPath, _ := filepath.Abs(socketPath)

	fmt.Println()
	fmt.Println("TUNNEL SERVER (Unix Socket Forwarder)")
	fmt.Println("───────────────────────────────────────────────")
	fmt.Printf("  Device ID: %s\n", identity.CompactID)
	fmt.Printf("  Socket:    %s\n", absPath)
	fmt.Println("───────────────────────────────────────────────")
	fmt.Println()

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity: identity,
		// Custom dialer for Unix socket!
		TargetDialer: func() (net.Conn, error) {
			return net.Dial("unix", socketPath)
		},
		OnConnect: func(clientID string) {
			log.Printf("✓ Client connected: %s", clientID)
		},
		OnDisconnect: func(clientID string) {
			log.Printf("○ Client disconnected: %s", clientID)
		},
		OnRelayJoined: func(relayAddr, persistentID, deviceIDWithHint string) {
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════")
			fmt.Println("  READY - Share this ID with clients:")
			fmt.Printf("  %s\n", deviceIDWithHint)
			fmt.Println("═══════════════════════════════════════════════")
			fmt.Println()
		},
		Logger: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := server.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("Server error: %v", err)
	}
}

func runClient(targetID, listenAddr, keyFile string) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity, err := tunnel.LoadOrGenerateIdentity(keyFile + ".client")
	if err != nil {
		log.Fatalf("Failed to load identity: %v", err)
	}

	fmt.Println()
	fmt.Println("TUNNEL CLIENT")
	fmt.Println("───────────────────────────────────────────────")
	fmt.Printf("  Client ID: %s\n", identity.CompactID)
	fmt.Printf("  Target:    %s\n", targetID)
	fmt.Printf("  Listen:    %s\n", listenAddr)
	fmt.Println("───────────────────────────────────────────────")
	fmt.Println()

	client, err := tunnel.NewClient(tunnel.ClientConfig{
		Identity:   identity,
		TargetID:   targetID,
		ListenAddr: listenAddr,
		OnTunnelEstablished: func() {
			log.Printf("✓ Tunnel ready! Connect to %s", listenAddr)
		},
		OnTunnelLost: func(err error) {
			log.Printf("✗ Tunnel lost: %v", err)
		},
		Logger: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("Client error: %v", err)
	}
}
