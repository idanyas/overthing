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
	flag.Parse()

	if *showConfig {
		showAllConfigurations()
	}

	if *runDemo {
		runDemoServer()
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
  // Use this for Unix sockets, named pipes, or in-memory connections
  TargetDialer func() (net.Conn, error)

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
  // Formats: 43 chars (compact), 51 chars (compact+hint),
  //          56 chars (standard), 66 chars (standard+hint)
  TargetID string

  // Local address to listen on (default: "127.0.0.1:2222")
  ListenAddr string

  // Custom listener (overrides ListenAddr)
  // Use this for Unix sockets or custom net.Listener implementations
  Listener net.Listener

  // Specific relay to use (empty = use hint from ID or discover)
  RelayURI string

  // Delay between reconnection attempts (default: 500ms)
  ReconnectDelay time.Duration

  // Callbacks
  OnTunnelEstablished func()       // Tunnel is ready
  OnTunnelLost        func(error)  // Tunnel connection lost

  // Custom logger (nil = silent)
  Logger func(level, message string)`)
	fmt.Println()

	// IDENTITY MANAGEMENT
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  IDENTITY MANAGEMENT")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println(`  // Generate ephemeral identity (not saved)
  identity := tunnel.GenerateIdentity()

  // Load from file (or generate and save if missing)
  identity, err := tunnel.LoadOrGenerateIdentity("/path/to/identity.key")

  // Load existing identity (fails if file missing)
  identity, err := tunnel.LoadIdentity("/path/to/identity.key")

  // Identity contains:
  //   Certificate tls.Certificate  - TLS cert for connections
  //   FullID      string           - 56-char Syncthing format ID
  //   CompactID   string           - 43-char compact format ID`)
	fmt.Println()

	// CUSTOM NETWORKING
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  CUSTOM NETWORKING PATTERNS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  1. Forward to Unix Socket (Server):")
	fmt.Println("  ─────────────────────────────────────")
	fmt.Println(`     tunnel.ServerConfig{
         TargetDialer: func() (net.Conn, error) {
             return net.Dial("unix", "/var/run/myapp.sock")
         },
     }`)
	fmt.Println()
	fmt.Println("  2. Listen on Unix Socket (Client):")
	fmt.Println("  ───────────────────────────────────")
	fmt.Println(`     listener, _ := net.Listen("unix", "/tmp/tunnel.sock")
     tunnel.ClientConfig{
         Listener: listener,
     }`)
	fmt.Println()
	fmt.Println("  3. In-Memory Testing with net.Pipe():")
	fmt.Println("  ─────────────────────────────────────")
	fmt.Println(`     // Server side - accept pipes
     tunnel.ServerConfig{
         TargetDialer: func() (net.Conn, error) {
             client, server := net.Pipe()
             go handleService(server)  // Your service logic
             return client, nil
         },
     }`)
	fmt.Println()
	fmt.Println("  4. Custom TLS Listener (Client):")
	fmt.Println("  ─────────────────────────────────")
	fmt.Println(`     tlsListener := tls.NewListener(tcpListener, tlsConfig)
     tunnel.ClientConfig{
         Listener: tlsListener,
     }`)
	fmt.Println()

	// DEVICE ID FORMATS
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  DEVICE ID FORMATS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("  ┌────────────────┬────────┬─────────────────────────────────────────────┐")
	fmt.Println("  │ Format         │ Length │ Description                                 │")
	fmt.Println("  ├────────────────┼────────┼─────────────────────────────────────────────┤")
	fmt.Println("  │ Compact        │ 43     │ Base63 encoded (URL-safe)                   │")
	fmt.Println("  │ Compact+Hint   │ 51     │ Compact + 8-char relay hint                 │")
	fmt.Println("  │ Standard       │ 56     │ Syncthing format with Luhn checksums        │")
	fmt.Println("  │ Standard+Hint  │ 66     │ Standard + 10-char Base32 relay hint        │")
	fmt.Println("  └────────────────┴────────┴─────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Example Compact ID:")
	fmt.Println("    QAV07YUWsUlUEVsxQyHUPHvpKd86w0jaEnkUZPI_WLA")
	fmt.Println()
	fmt.Println("  Example Compact+Hint ID:")
	fmt.Println("    QAV07YUWsUlUEVsxQyHUPHvpKd86w0jaEnkUZPI_WLAAbCdEfGh")
	fmt.Println("                                               ^^^^^^^^")
	fmt.Println("                                               Relay hint")
	fmt.Println()

	// CALLBACKS AND LOGGING
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println("  LOGGING AND CALLBACKS")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Printf("%s\n", `  Logger: func(level, message string) {
      // Levels: "info", "ok", "warn", "error"
      switch level {
      case "error":
          log.Printf("[ERROR] %s", message)
      case "warn":
          log.Printf("[WARN] %s", message)
      case "ok":
          log.Printf("[OK] %s", message)
      default:
          if verbose {
              log.Printf("[INFO] %s", message)
          }
      }
  }`)
	fmt.Println()
}

func runDemoServer() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity := tunnel.GenerateIdentity()

	fmt.Println()
	fmt.Println("Starting demo server with all features enabled...")
	fmt.Println()

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity:       identity,
		ForwardAddr:    "127.0.0.1:22",
		ReconnectDelay: 1 * time.Second,

		// Custom target dialer example (using TCP but could be Unix socket)
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
			log.Printf("    ID+Hint: %s", deviceIDWithHint)
		},
		Logger: func(level, msg string) {
			log.Printf("  [%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	server.Run(ctx)
}
