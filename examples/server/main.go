// Tunnel server - automatically discovers fastest relay
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"tunnel"
)

func main() {
	relayURI := flag.String("relay", "", "Relay URI (auto-discover if empty)")
	forwardAddr := flag.String("forward", "127.0.0.1:8080", "Address to forward connections to")
	keyFile := flag.String("key", "./server.key", "Identity key file")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity, err := tunnel.LoadOrGenerateIdentity(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Device ID: %s", identity.CompactID)
	log.Printf("Full ID:   %s", identity.FullID)

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity:    identity,
		RelayURI:    *relayURI, // Empty = auto-discover
		ForwardAddr: *forwardAddr,
		OnConnect: func(clientID string) {
			log.Printf("Client connected: %s", clientID)
		},
		OnDisconnect: func(clientID string) {
			log.Printf("Client disconnected: %s", clientID)
		},
		Logger: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Using relay: %s", server.RelayURI())
	log.Println("Starting server... Press Ctrl+C to stop")
	
	if err := server.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	log.Println("Server stopped")
}
