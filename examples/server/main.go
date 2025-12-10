package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"tunnel"
)

func main() {
	relayURI := flag.String("relay", "", "Relay URI (auto-discover if empty)")
	forwardAddr := flag.String("forward", "127.0.0.1:22", "Address to forward connections to")
	keyFile := flag.String("key", "./server.key", "Identity key file")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity, err := tunnel.LoadOrGenerateIdentity(*keyFile)
	if err != nil {
		log.Fatal(err)
	}

	absKeyPath, _ := filepath.Abs(*keyFile)

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity:    identity,
		RelayURI:    *relayURI,
		ForwardAddr: *forwardAddr,
		OnConnect: func(clientID string) {
			log.Printf("Client connected: %s", clientID)
		},
		OnDisconnect: func(clientID string) {
			log.Printf("Client disconnected: %s", clientID)
		},
		OnRelayJoined: func(relayAddr, persistentID, deviceIDWithHint string) {
			fmt.Println()
			fmt.Println("RELAY TUNNEL SERVER")
			fmt.Println(strings.Repeat("-", 19))
			fmt.Printf("  Persistent ID: %s\n", persistentID)
			fmt.Printf("  ID with Hint:  %s\n", deviceIDWithHint)
			fmt.Printf("  Forward:       %s\n", *forwardAddr)
			fmt.Printf("  Identity:      %s\n", absKeyPath)
			fmt.Println()
		},
		Logger: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting server... Press Ctrl+C to stop")
	
	if err := server.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	log.Println("Server stopped")
}
