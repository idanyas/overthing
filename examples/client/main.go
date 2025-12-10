// Tunnel client - uses relay hint from Device ID or discovers
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"tunnel"
)

func main() {
	relayURI := flag.String("relay", "", "Relay URI (uses hint from ID if empty)")
	listenAddr := flag.String("listen", "127.0.0.1:2222", "Local address to listen on")
	keyFile := flag.String("key", "", "Identity key file (ephemeral if empty)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <server-device-id>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Device ID formats:\n")
		fmt.Fprintf(os.Stderr, "  43 chars: Plain ID (requires discovery)\n")
		fmt.Fprintf(os.Stderr, "  51 chars: ID with relay hint (direct connection)\n\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	serverID := flag.Arg(0)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var identity tunnel.Identity
	var err error
	if *keyFile != "" {
		identity, err = tunnel.LoadOrGenerateIdentity(*keyFile)
	} else {
		identity = tunnel.GenerateIdentity()
	}
	if err != nil {
		log.Fatal(err)
	}

	// Show info about the target ID
	fmt.Println()
	fmt.Println("RELAY TUNNEL CLIENT")
	fmt.Println(strings.Repeat("-", 19))
	fmt.Printf("  Client ID: %s\n", identity.CompactID)
	fmt.Printf("  Target:    %s\n", serverID)
	if len(serverID) == 51 {
		fmt.Printf("             (includes relay hint)\n")
	} else if len(serverID) == 43 {
		fmt.Printf("             (no hint - will discover)\n")
	}
	fmt.Printf("  Listen:    %s\n", *listenAddr)
	fmt.Println()

	client, err := tunnel.NewClient(tunnel.ClientConfig{
		Identity:   identity,
		TargetID:   serverID,
		RelayURI:   *relayURI,
		ListenAddr: *listenAddr,
		OnTunnelEstablished: func() {
			log.Printf("Ready! Connect to %s", *listenAddr)
		},
		OnTunnelLost: func(err error) {
			log.Printf("Tunnel lost: %v (reconnecting...)", err)
		},
		Logger: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
