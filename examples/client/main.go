// Tunnel client - automatically discovers fastest relay
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"tunnel"
)

func main() {
	relayURI := flag.String("relay", "", "Relay URI (auto-discover if empty)")
	listenAddr := flag.String("listen", "127.0.0.1:9000", "Local address to listen on")
	keyFile := flag.String("key", "./client.key", "Identity key file")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <server-device-id>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	serverID := flag.Arg(0)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity, err := tunnel.LoadOrGenerateIdentity(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Client ID: %s", identity.CompactID)

	client, err := tunnel.NewClient(tunnel.ClientConfig{
		Identity:   identity,
		TargetID:   serverID,
		RelayURI:   *relayURI, // Empty = auto-discover
		ListenAddr: *listenAddr,
		OnTunnelEstablished: func() {
			log.Printf("Tunnel established! Connect to %s", *listenAddr)
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

	log.Printf("Using relay: %s", client.RelayURI())
	log.Println("Starting client... Press Ctrl+C to stop")
	
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	log.Println("Client stopped")
}
