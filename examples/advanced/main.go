// Advanced configuration example showing all options
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	tunnel "github.com/idanyas/overthing"
)

func main() {
	showConfig := flag.Bool("show-config", true, "Show all configuration options")
	runDemo := flag.Bool("demo", false, "Run a demo server")
	bindIP := flag.String("bind-ip", "", "Example: Bind outgoing connections to specific local IP")
	flag.Parse()

	if *showConfig {
		showAllConfigurations()
	}

	if *runDemo {
		runDemoServer(*bindIP)
	}
}

func showAllConfigurations() {
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              TUNNEL LIBRARY - ALL CONFIGURATION OPTIONS                ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// SERVER CONFIGURATION
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  SERVER CONFIGURATION (tunnel.ServerConfig)")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(`  // Required - The server's cryptographic identity
  Identity tunnel.Identity

  // Target address to forward connections to (default: "127.0.0.1:22")
  ForwardAddr string

  // Custom dialer for non-TCP targets (overrides ForwardAddr)
  TargetDialer func() (net.Conn, error)

  // Custom dialer for outgoing connections (Relay)
  // Use this to bind to a specific network interface or use a proxy
  Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

  // Specific relay to use (empty = auto-discover fastest)
  RelayURI string

  // Delay between reconnection attempts (default: 500ms)
  ReconnectDelay time.Duration

  // List of allowed client Device IDs (empty = allow all)
  AllowedClientIDs []string

  // Explicitly allow any client (redundant if AllowedClientIDs is empty)
  AllowAnyClient bool

  // Callbacks
  OnConnect     func(clientID string)            // Client connected
  OnDisconnect  func(clientID string)            // Client disconnected
  OnRelayJoined func(relay, id, idWithHint string) // Joined relay

  // Custom logger (nil = silent)
  Logger func(level, message string)`)
	fmt.Println()

	// CLIENT CONFIGURATION
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  CLIENT CONFIGURATION (tunnel.ClientConfig)")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(`  // Required - The client's cryptographic identity
  Identity tunnel.Identity

  // Required - Device ID of the server to connect to
  TargetID string

  // Local address to listen on (default: "127.0.0.1:2222")
  ListenAddr string

  // Custom listener (overrides ListenAddr)
  Listener net.Listener

  // Specific relay to use (empty = use hint from ID or discover)
  RelayURI string

  // Custom dialer for outgoing connections (Relay)
  Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

  // Delay between reconnection attempts (default: 500ms)
  ReconnectDelay time.Duration

  // Callbacks
  OnTunnelEstablished func()       // Tunnel is ready
  OnTunnelLost        func(error)  // Tunnel connection lost

  // Custom logger (nil = silent)
  Logger func(level, message string)`)
	fmt.Println()

	// CUSTOM NETWORKING
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  CUSTOM NETWORKING PATTERNS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  1. Bind outgoing traffic to specific Interface/IP:")
	fmt.Println("  ──────────────────────────────────────────────────")
	fmt.Println(`     localAddr := &net.TCPAddr{IP: net.ParseIP("192.168.1.50")}
     dialer := &net.Dialer{LocalAddr: localAddr}

     cfg := tunnel.ClientConfig{
         Dialer: dialer.DialContext,
         // ...
     }`)
	fmt.Println()
	fmt.Println("  2. Forward to Unix Socket (Server):")
	fmt.Println("  ─────────────────────────────────────")
	fmt.Println(`     tunnel.ServerConfig{
         TargetDialer: func() (net.Conn, error) {
             return net.Dial("unix", "/var/run/myapp.sock")
         },
     }`)
	fmt.Println()
}

func runDemoServer(bindIP string) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity := tunnel.GenerateIdentity()

	fmt.Println()
	fmt.Println("Starting demo server with all features enabled...")
	fmt.Println()

	cfg := tunnel.ServerConfig{
		Identity:       identity,
		ForwardAddr:    "127.0.0.1:22",
		ReconnectDelay: 1 * time.Second,

		// Custom target dialer example
		TargetDialer: func() (net.Conn, error) {
			log.Println("  → Custom TargetDialer called")
			return net.DialTimeout("tcp", "127.0.0.1:22", 5*time.Second)
		},

		OnConnect: func(clientID string) {
			log.Printf("  → OnConnect: %s", clientID)
		},
		OnDisconnect: func(clientID string) {
			log.Printf("  → OnDisconnect: %s", clientID)
		},
		OnRelayJoined: func(relayAddr, persistentID, deviceIDWithHint string) {
			log.Println("  → OnRelayJoined callback fired")
			log.Printf("    Relay: %s", relayAddr)
			log.Printf("    ID: %s", persistentID)
		},
		Logger: func(level, msg string) {
			log.Printf("  [%s] %s", level, msg)
		},
	}

	if bindIP != "" {
		ip := net.ParseIP(bindIP)
		if ip == nil {
			log.Fatalf("Invalid IP: %s", bindIP)
		}
		fmt.Printf("Binding outgoing relay connections to: %s\n", ip)
		
		d := &net.Dialer{
			LocalAddr: &net.TCPAddr{IP: ip},
			Timeout:   10 * time.Second,
		}
		cfg.Dialer = d.DialContext
	}

	server, err := tunnel.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	server.Run(ctx)
}
