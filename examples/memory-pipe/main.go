// In-memory pipe example for testing without real network
// Uses net.Pipe() for in-process communication
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/idanyas/overthing"
)

func main() {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║            IN-MEMORY PIPE TUNNEL DEMONSTRATION                 ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("This example demonstrates using net.Pipe() for in-memory testing.")
	fmt.Println("No network access is required - everything runs in-process.")
	fmt.Println()

	// Example 1: Direct pipe communication
	fmt.Println("═══ Example 1: Direct net.Pipe() ═══")
	fmt.Println()
	demonstrateDirectPipe()

	// Example 2: Custom listener with pipes
	fmt.Println()
	fmt.Println("═══ Example 2: Custom Listener with Pipes ═══")
	fmt.Println()
	demonstrateCustomListener()

	// Example 3: Full tunnel with memory transport
	fmt.Println()
	fmt.Println("═══ Example 3: In-Memory Echo Service ═══")
	fmt.Println()
	demonstrateMemoryEchoService()

	fmt.Println()
	fmt.Println("All examples completed successfully!")
}

// demonstrateDirectPipe shows basic net.Pipe() usage
func demonstrateDirectPipe() {
	// net.Pipe() creates a synchronous, in-memory, full duplex connection
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// Server goroutine
	go func() {
		buf := make([]byte, 1024)
		n, _ := server.Read(buf)
		fmt.Printf("  Server received: %q\n", buf[:n])
		server.Write([]byte("Hello from server!"))
	}()

	// Client sends and receives
	client.Write([]byte("Hello from client!"))
	
	buf := make([]byte, 1024)
	n, _ := client.Read(buf)
	fmt.Printf("  Client received: %q\n", buf[:n])
}

// pipeListener implements net.Listener using net.Pipe()
type pipeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		conns:  make(chan net.Conn, 10),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr{}
}

// Dial creates a new pipe and sends one end to the listener
func (l *pipeListener) Dial() (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		client.Close()
		server.Close()
		return nil, net.ErrClosed
	}
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "memory:pipe" }

// demonstrateCustomListener shows using a custom listener
func demonstrateCustomListener() {
	listener := newPipeListener()
	defer listener.Close()

	// Start acceptor goroutine
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				fmt.Printf("  Listener received: %q\n", buf[:n])
				c.Write([]byte("Acknowledged!"))
			}(conn)
		}
	}()

	// Dial through the custom listener
	conn, err := listener.Dial()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	conn.Write([]byte("Testing custom listener"))
	
	buf := make([]byte, 1024)
	n, _ := conn.Read(buf)
	fmt.Printf("  Dialer received: %q\n", buf[:n])
}

// demonstrateMemoryEchoService shows a complete in-memory service
func demonstrateMemoryEchoService() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create in-memory listener for client
	clientListener := newPipeListener()
	defer clientListener.Close()

	// Create in-memory connection for server's target
	serverConns := make(chan net.Conn, 10)

	// Echo service (simulates the service being forwarded to)
	go func() {
		for conn := range serverConns {
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // Echo everything back
			}(conn)
		}
	}()

	// Generate identities
	serverIdentity := tunnel.GenerateIdentity()
	clientIdentity := tunnel.GenerateIdentity()

	fmt.Printf("  Server ID: %s\n", serverIdentity.CompactID[:20]+"...")
	fmt.Printf("  Client ID: %s\n", clientIdentity.CompactID[:20]+"...")
	fmt.Println()

	// In a real scenario, you'd run the full tunnel.
	// Here we just demonstrate the pattern:
	fmt.Println("  Pattern: Client Listener -> Tunnel -> Server TargetDialer")
	fmt.Println()
	fmt.Println("  ServerConfig.TargetDialer can dial to:")
	fmt.Println("    - Unix sockets:  net.Dial(\"unix\", \"/path/to/socket\")")
	fmt.Println("    - TCP:           net.Dial(\"tcp\", \"host:port\")")
	fmt.Println("    - Memory pipes:  Create net.Pipe() and return one end")
	fmt.Println()
	fmt.Println("  ClientConfig.Listener can be:")
	fmt.Println("    - TCP listener:  net.Listen(\"tcp\", \":8080\")")
	fmt.Println("    - Unix socket:   net.Listen(\"unix\", \"/tmp/tunnel.sock\")")
	fmt.Println("    - Custom:        Any net.Listener implementation")

	// Demonstrate the TargetDialer pattern
	_ = tunnel.ServerConfig{
		Identity: serverIdentity,
		// This is how you'd forward to an in-memory service:
		TargetDialer: func() (net.Conn, error) {
			client, server := net.Pipe()
			select {
			case serverConns <- server:
				return client, nil
			default:
				client.Close()
				server.Close()
				return nil, fmt.Errorf("service busy")
			}
		},
	}

	// Demonstrate the Listener pattern
	_ = tunnel.ClientConfig{
		Identity: clientIdentity,
		TargetID: serverIdentity.CompactID,
		// This is how you'd use a custom listener:
		Listener: clientListener,
	}

	<-ctx.Done()
}
