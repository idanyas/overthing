// Tunnel server example with comprehensive logging and configuration display
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
	"strings"
	"sync/atomic"
	"time"

	"github.com/idanyas/overthing"
)

var (
	activeClients   int64
	totalClients    int64
	totalStreams    int64
	startTime       time.Time
	lastClientTime  time.Time
)

func main() {
	// Flags
	relayURI := flag.String("relay", "", "Relay URI (auto-discover if empty)")
	forwardAddr := flag.String("forward", "127.0.0.1:22", "Address to forward connections to")
	keyFile := flag.String("key", "./server.key", "Identity key file")
	verbose := flag.Bool("v", false, "Verbose logging")
	showStats := flag.Bool("stats", false, "Show periodic statistics")
	statsInterval := flag.Duration("stats-interval", 30*time.Second, "Statistics display interval")
	allowedClients := flag.String("allowed", "", "Comma-separated list of allowed client IDs (empty = allow all)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Tunnel Server - Secure NAT-traversing TCP tunnel server

USAGE:
    %s [OPTIONS]

DESCRIPTION:
    Starts a tunnel server that accepts connections from tunnel clients
    and forwards them to a local service (e.g., SSH, HTTP, database).

EXAMPLES:
    # Basic SSH forwarding (default)
    %s

    # Forward to a web server
    %s -forward 127.0.0.1:8080

    # Use custom identity file
    %s -key /etc/tunnel/server.key -forward 127.0.0.1:3306

    # Restrict to specific clients
    %s -allowed "ClientID1,ClientID2"

    # Verbose mode with statistics
    %s -v -stats

OPTIONS:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
ACCESS CONTROL:
    By default, the server allows ALL clients to connect.
    Use -allowed to restrict access to specific Device IDs.

IDENTITY:
    The server generates a persistent identity on first run.
    Share the "ID with Hint" with clients for instant connections.
    The "Persistent ID" works even if the relay changes.

For more information: https://github.com/idanyas/overthing
`)
	}
	flag.Parse()

	startTime = time.Now()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// Load identity
	identity, err := tunnel.LoadOrGenerateIdentity(*keyFile)
	if err != nil {
		log.Fatalf("Failed to load identity: %v", err)
	}

	absKeyPath, _ := filepath.Abs(*keyFile)

	// Parse allowed clients
	var allowedList []string
	if *allowedClients != "" {
		for _, id := range strings.Split(*allowedClients, ",") {
			id = strings.TrimSpace(id)
			if id != "" {
				allowedList = append(allowedList, id)
			}
		}
	}

	// Verify forward address is reachable
	forwardStatus := checkForwardAddr(*forwardAddr)

	// Print banner
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                     TUNNEL SERVER                              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  %-18s %s\n", "Version:", tunnel.Version)
	fmt.Printf("  %-18s %s/%s\n", "Platform:", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  %-18s %d\n", "Max Goroutines:", runtime.GOMAXPROCS(0)*1000)
	fmt.Println()
	fmt.Println("  ─── Identity ───")
	fmt.Printf("  %-18s %s\n", "Compact ID:", identity.CompactID)
	fmt.Printf("  %-18s %s\n", "Full ID:", identity.FullID)
	fmt.Printf("  %-18s %s\n", "Key File:", absKeyPath)
	fmt.Println()
	fmt.Println("  ─── Forwarding ───")
	fmt.Printf("  %-18s %s %s\n", "Target:", *forwardAddr, forwardStatus)
	fmt.Println()
	fmt.Println("  ─── Access Control ───")
	if len(allowedList) > 0 {
		fmt.Printf("  %-18s %d client(s) whitelisted\n", "Mode:", len(allowedList))
		for i, id := range allowedList {
			if i < 3 {
				fmt.Printf("  %-18s %s\n", fmt.Sprintf("  Client %d:", i+1), truncateID(id, 50))
			}
		}
		if len(allowedList) > 3 {
			fmt.Printf("  %-18s ... and %d more\n", "", len(allowedList)-3)
		}
	} else {
		fmt.Printf("  %-18s OPEN (all clients allowed)\n", "Mode:")
	}
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println()

	// Stats reporter
	if *showStats {
		go statsReporter(ctx, *statsInterval)
	}

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity:         identity,
		RelayURI:         *relayURI,
		ForwardAddr:      *forwardAddr,
		AllowedClientIDs: allowedList,
		OnConnect: func(clientID string) {
			atomic.AddInt64(&activeClients, 1)
			atomic.AddInt64(&totalClients, 1)
			lastClientTime = time.Now()
			log.Printf("✓ Client CONNECTED: %s (active: %d)", clientID, atomic.LoadInt64(&activeClients))
		},
		OnDisconnect: func(clientID string) {
			atomic.AddInt64(&activeClients, -1)
			log.Printf("○ Client DISCONNECTED: %s (active: %d)", clientID, atomic.LoadInt64(&activeClients))
		},
		OnRelayJoined: func(relayAddr, persistentID, deviceIDWithHint string) {
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════════════")
			fmt.Println("  🔗 CONNECTED TO RELAY")
			fmt.Println("═══════════════════════════════════════════════════════════════════")
			fmt.Println()
			fmt.Println("  Share one of these IDs with clients:")
			fmt.Println()
			fmt.Printf("  %-18s %s\n", "ID with Hint:", deviceIDWithHint)
			fmt.Printf("  %-18s (51 chars - includes relay address for instant connection)\n", "")
			fmt.Println()
			fmt.Printf("  %-18s %s\n", "Persistent ID:", persistentID)
			fmt.Printf("  %-18s (43 chars - works even if relay changes, ~2-5s discovery)\n", "")
			fmt.Println()
			fmt.Printf("  %-18s %s\n", "Relay Address:", relayAddr)
			fmt.Println()
			fmt.Println("═══════════════════════════════════════════════════════════════════")
			fmt.Println()
			log.Println("Server is READY and waiting for connections...")
		},
		Logger: func(level, msg string) {
			if *verbose || level == "ok" || level == "error" || level == "warn" {
				prefix := levelPrefix(level)
				log.Printf("%s %s", prefix, msg)
			}
		},
	})
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Println("Discovering fastest relay... (this may take a few seconds)")

	if err := server.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("Server error: %v", err)
	}

	printFinalStats()
}

func checkForwardAddr(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "⚠ (not reachable - start your service!)"
	}
	conn.Close()
	return "✓ (reachable)"
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
			active := atomic.LoadInt64(&activeClients)
			total := atomic.LoadInt64(&totalClients)
			uptime := time.Since(startTime).Round(time.Second)
			
			var lastSeen string
			if !lastClientTime.IsZero() {
				lastSeen = time.Since(lastClientTime).Round(time.Second).String() + " ago"
			} else {
				lastSeen = "never"
			}

			log.Printf("📊 STATS | Uptime: %s | Active: %d | Total: %d | Last: %s",
				uptime, active, total, lastSeen)
		}
	}
}

func printFinalStats() {
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println("  SESSION SUMMARY")
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Printf("  %-18s %s\n", "Total Uptime:", time.Since(startTime).Round(time.Second))
	fmt.Printf("  %-18s %d\n", "Total Clients:", atomic.LoadInt64(&totalClients))
	fmt.Printf("  %-18s %d\n", "Total Streams:", atomic.LoadInt64(&totalStreams))
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println()
}
