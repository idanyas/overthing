// Tunnel client example with comprehensive logging and configuration display
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	tunnel "github.com/idanyas/overthing"
)

var (
	bytesIn      int64
	bytesOut     int64
	connections  int64
	startTime    time.Time
	tunnelUptime time.Time
)

func main() {
	// Flags
	relayURI := flag.String("relay", "", "Relay URI (uses hint from ID if empty)")
	listenAddr := flag.String("listen", "127.0.0.1:2222", "Local address to listen on")
	keyFile := flag.String("key", "", "Identity key file (ephemeral if empty)")
	verbose := flag.Bool("v", false, "Verbose logging")
	showStats := flag.Bool("stats", false, "Show periodic connection statistics")
	statsInterval := flag.Duration("stats-interval", 10*time.Second, "Statistics display interval")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Tunnel Client - Secure NAT-traversing TCP tunnel

USAGE:
    %s [OPTIONS] <server-device-id>

DEVICE ID FORMATS:
    43 chars   Compact ID (requires relay discovery, ~2-5s startup)
    51 chars   Compact ID + Relay Hint (instant connection)
    56 chars   Standard Syncthing ID (requires discovery)
    66 chars   Standard ID + Relay Hint (instant connection)

EXAMPLES:
    # Connect using ID with relay hint (fastest)
    %s QAV07YUWsUlUEVsxQyHUPHvpKd86w0jaEnkUZPI_WLAAbCdEfGh

    # Connect and listen on custom port
    %s -listen 0.0.0.0:8080 <device-id>

    # Use persistent identity
    %s -key ~/.tunnel-client.key <device-id>

    # Verbose mode with stats
    %s -v -stats -stats-interval 5s <device-id>

OPTIONS:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
ENVIRONMENT:
    NO_COLOR      Disable colored output
    FORCE_COLOR   Force colored output

For more information: https://github.com/idanyas/overthing
`)
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	serverID := flag.Arg(0)
	startTime = time.Now()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Load or generate identity
	var identity tunnel.Identity
	var err error
	var identitySource string

	if *keyFile != "" {
		identity, err = tunnel.LoadOrGenerateIdentity(*keyFile)
		if err != nil {
			log.Fatalf("Failed to load identity: %v", err)
		}
		absPath, _ := filepath.Abs(*keyFile)
		identitySource = absPath
	} else {
		identity = tunnel.GenerateIdentity()
		identitySource = "(ephemeral - not saved)"
	}

	// Analyze target ID
	idType, idInfo := analyzeDeviceID(serverID)

	// Print banner with configuration
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     TUNNEL CLIENT                              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  %-18s %s\n", "Version:", tunnel.Version)
	fmt.Printf("  %-18s %s/%s\n", "Platform:", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  %-18s %d\n", "Goroutines:", runtime.NumGoroutine())
	fmt.Println()
	fmt.Println("  ─── Identity ───")
	fmt.Printf("  %-18s %s\n", "Client ID:", identity.CompactID)
	fmt.Printf("  %-18s %s\n", "Full ID:", identity.FullID)
	fmt.Printf("  %-18s %s\n", "Key File:", identitySource)
	fmt.Println()
	fmt.Println("  ─── Target ───")
	fmt.Printf("  %-18s %s\n", "Device ID:", truncateID(serverID, 60))
	fmt.Printf("  %-18s %s\n", "ID Type:", idType)
	fmt.Printf("  %-18s %s\n", "Relay Info:", idInfo)
	fmt.Println()
	fmt.Println("  ─── Network ───")
	fmt.Printf("  %-18s %s\n", "Listen Address:", *listenAddr)
	if *relayURI != "" {
		fmt.Printf("  %-18s %s\n", "Relay Override:", *relayURI)
	}
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println()

	// Start stats reporter if enabled
	if *showStats {
		go statsReporter(ctx, *statsInterval)
	}

	client, err := tunnel.NewClient(tunnel.ClientConfig{
		Identity:   identity,
		TargetID:   serverID,
		RelayURI:   *relayURI,
		ListenAddr: *listenAddr,
		OnTunnelEstablished: func() {
			tunnelUptime = time.Now()
			log.Printf("✓ Tunnel READY - accepting connections on %s", *listenAddr)
			log.Printf("  → Connections will be forwarded through the secure tunnel")
		},
		OnTunnelLost: func(err error) {
			log.Printf("✗ Tunnel LOST: %v", err)
			log.Printf("  → Attempting automatic reconnection...")
		},
		Logger: func(level, msg string) {
			if *verbose || level == "ok" || level == "error" || level == "warn" {
				prefix := levelPrefix(level)
				log.Printf("%s %s", prefix, msg)
			}
		},
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	log.Println("Starting tunnel client... (Press Ctrl+C to stop)")
	log.Println()

	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("Client error: %v", err)
	}

	// Print final stats
	printFinalStats()
}

func analyzeDeviceID(id string) (idType, info string) {
	switch len(id) {
	case 43:
		return "Compact (Base63)", "No hint - will scan ~800 relays (~2-5s)"
	case 51:
		return "Compact + Hint", "Has relay hint - instant connection"
	case 56:
		return "Standard (Syncthing)", "No hint - will scan ~800 relays (~2-5s)"
	case 63, 66:
		return "Standard + Hint", "Has relay hint - instant connection"
	default:
		return "Unknown", fmt.Sprintf("Unusual length: %d chars", len(id))
	}
}

func truncateID(id string, maxLen int) string {
	if len(id) <= maxLen {
		return id
	}
	return id[:maxLen-3] + "..."
}

func levelPrefix(level string) string {
	switch level {
	case "ok":
		return "✓"
	case "info":
		return "ℹ"
	case "warn":
		return "⚠"
	case "error":
		return "✗"
	default:
		return "•"
	}
}

func statsReporter(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			in := atomic.LoadInt64(&bytesIn)
			out := atomic.LoadInt64(&bytesOut)
			conns := atomic.LoadInt64(&connections)
			uptime := time.Since(startTime).Round(time.Second)

			var tunnelUp string
			if !tunnelUptime.IsZero() {
				tunnelUp = time.Since(tunnelUptime).Round(time.Second).String()
			} else {
				tunnelUp = "connecting..."
			}

			log.Printf("📊 STATS | Uptime: %s | Tunnel: %s | Conns: %d | In: %s | Out: %s",
				uptime, tunnelUp, conns, formatBytes(in), formatBytes(out))
		}
	}
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func printFinalStats() {
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println("  SESSION SUMMARY")
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Printf("  %-18s %s\n", "Total Uptime:", time.Since(startTime).Round(time.Second))
	fmt.Printf("  %-18s %d\n", "Connections:", atomic.LoadInt64(&connections))
	fmt.Printf("  %-18s %s\n", "Data In:", formatBytes(atomic.LoadInt64(&bytesIn)))
	fmt.Printf("  %-18s %s\n", "Data Out:", formatBytes(atomic.LoadInt64(&bytesOut)))
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println()
}
