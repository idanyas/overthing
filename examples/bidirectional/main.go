// Bidirectional tunnel example - runs both client and server in one process
// Useful for testing and demonstration without multiple terminals
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	tunnel "github.com/idanyas/overthing"
)

func main() {
	echoPort := flag.Int("echo-port", 9999, "Port for local echo server")
	clientPort := flag.Int("client-port", 2222, "Port for tunnel client to listen on")
	testData := flag.String("test", "Hello through the tunnel!", "Test message to send")
	autoTest := flag.Bool("auto-test", true, "Automatically test the tunnel")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Bidirectional Tunnel Test

This example runs everything in a single process:
1. An echo server (simulates the service to tunnel)
2. A tunnel server (forwards to the echo server)
3. A tunnel client (exposes the tunnel locally)
4. A test that sends data through the tunnel

This demonstrates the complete tunnel flow without needing multiple terminals.

USAGE:
    %s [OPTIONS]

OPTIONS:
`, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              BIDIRECTIONAL TUNNEL TEST                         ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Step 1: Start echo server
	echoAddr := fmt.Sprintf("127.0.0.1:%d", *echoPort)
	fmt.Printf("1. Starting echo server on %s...\n", echoAddr)

	echoListener, err := net.Listen("tcp", echoAddr)
	if err != nil {
		log.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	go runEchoServer(ctx, echoListener)
	fmt.Println("   ✓ Echo server ready")

	// Step 2: Start tunnel server
	fmt.Println()
	fmt.Println("2. Starting tunnel server...")

	serverIdentity := tunnel.GenerateIdentity()
	fmt.Printf("   Server ID: %s\n", serverIdentity.CompactID)

	var serverDeviceID string
	serverReady := make(chan struct{})

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity:    serverIdentity,
		ForwardAddr: echoAddr,
		OnRelayJoined: func(relayAddr, persistentID, deviceIDWithHint string) {
			serverDeviceID = deviceIDWithHint
			fmt.Printf("   Joined relay: %s\n", relayAddr)
			fmt.Printf("   Device ID with hint: %s\n", deviceIDWithHint)
			close(serverReady)
		},
		Logger: func(level, msg string) {
			if level == "error" {
				log.Printf("   [server/%s] %s", level, msg)
			}
		},
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		if err := server.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for server to join relay
	select {
	case <-serverReady:
		fmt.Println("   ✓ Tunnel server ready")
	case <-time.After(30 * time.Second):
		log.Fatal("Timeout waiting for server to join relay")
	case <-ctx.Done():
		return
	}

	// Step 3: Start tunnel client
	fmt.Println()
	fmt.Println("3. Starting tunnel client...")

	clientAddr := fmt.Sprintf("127.0.0.1:%d", *clientPort)
	clientIdentity := tunnel.GenerateIdentity()
	fmt.Printf("   Client ID: %s\n", clientIdentity.CompactID)
	fmt.Printf("   Connecting to: %s\n", truncateID(serverDeviceID, 50))

	clientReady := make(chan struct{})

	client, err := tunnel.NewClient(tunnel.ClientConfig{
		Identity:   clientIdentity,
		TargetID:   serverDeviceID,
		ListenAddr: clientAddr,
		OnTunnelEstablished: func() {
			close(clientReady)
		},
		Logger: func(level, msg string) {
			if level == "error" || level == "ok" {
				log.Printf("   [client/%s] %s", level, msg)
			}
		},
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	go func() {
		if err := client.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("Client error: %v", err)
		}
	}()

	// Wait for tunnel to establish
	select {
	case <-clientReady:
		fmt.Println("   ✓ Tunnel client ready")
	case <-time.After(30 * time.Second):
		log.Fatal("Timeout waiting for tunnel to establish")
	case <-ctx.Done():
		return
	}

	// Step 4: Test the tunnel
	if *autoTest {
		fmt.Println()
		fmt.Println("4. Testing tunnel...")
		fmt.Println()

		time.Sleep(500 * time.Millisecond) // Brief pause for stability

		conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
		if err != nil {
			log.Fatalf("Failed to connect through tunnel: %v", err)
		}
		defer conn.Close()

		fmt.Printf("   → Sending: %q\n", *testData)
		_, err = conn.Write([]byte(*testData))
		if err != nil {
			log.Fatalf("Failed to send: %v", err)
		}

		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			log.Fatalf("Failed to receive: %v", err)
		}

		fmt.Printf("   ← Received: %q\n", buf[:n])

		if string(buf[:n]) == *testData {
			fmt.Println()
			fmt.Println("   ✓ SUCCESS! Data passed through tunnel correctly")
		} else {
			fmt.Println()
			fmt.Println("   ✗ MISMATCH: Received data doesn't match sent data")
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════")
	fmt.Println("  All components running. Press Ctrl+C to stop.")
	fmt.Println()
	fmt.Printf("  Connect to the tunnel at: %s\n", clientAddr)
	fmt.Printf("  Example: nc %s %d\n", "localhost", *clientPort)
	fmt.Println("═══════════════════════════════════════════════════════════════════")

	<-ctx.Done()
	fmt.Println("\nShutting down...")
}

func runEchoServer(ctx context.Context, listener net.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			io.Copy(c, c)
		}(conn)
	}
}

func truncateID(id string, maxLen int) string {
	if len(id) <= maxLen {
		return id
	}
	return id[:maxLen-3] + "..."
}
