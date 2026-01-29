package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	tunnel "github.com/idanyas/overthing"
	"github.com/idanyas/overthing/pkg/logging"
)

func main() {
	// Subcommands
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		runServer(os.Args[2:])
	case "client":
		runClient(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <command> [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  server    Start tunnel server\n")
	fmt.Fprintf(os.Stderr, "  client    Start tunnel client\n")
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	identityFile := fs.String("identity", "", "Identity key file")
	forwardAddr := fs.String("forward", "127.0.0.1:22", "Address to forward connections to")
	relayURI := fs.String("relay", "", "Relay URI (auto-discover if empty)")
	fs.Parse(args)

	if *identityFile == "" {
		fmt.Fprintln(os.Stderr, "Error: -identity is required")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	identity, err := tunnel.LoadOrGenerateIdentity(*identityFile)
	if err != nil {
		logging.Fatal("Failed to load identity: %v", err)
	}

	absIdentityPath, _ := filepath.Abs(*identityFile)

	server, err := tunnel.NewServer(tunnel.ServerConfig{
		Identity:    identity,
		RelayURI:    *relayURI,
		ForwardAddr: *forwardAddr,
		OnConnect: func(clientID string) {
			logging.Info("Client connected: %s", clientID)
		},
		OnDisconnect: func(clientID string) {
			logging.Info("Client disconnected: %s", clientID)
		},
		OnRelayJoined: func(relayAddr, persistentID, deviceIDWithHint string) {
			logging.Banner("RELAY TUNNEL SERVER")
			logging.Field("Persistent ID", persistentID)
			logging.Field("ID with Hint", deviceIDWithHint)
			logging.Field("Forward", *forwardAddr)
			logging.Field("Identity", absIdentityPath)
			logging.Blank()
		},
		Logger: func(level, msg string) {
			logging.Log(level, msg)
		},
	})
	if err != nil {
		logging.Fatal("Failed to create server: %v", err)
	}

	if err := server.Run(ctx); err != nil && ctx.Err() == nil {
		logging.Fatal("Server error: %v", err)
	}
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	targetIDFlag := fs.String("target", "", "Server Device ID (with or without relay hint)")
	listenAddr := fs.String("listen", "127.0.0.1:2222", "Local address to listen on")
	identityFile := fs.String("identity", "", "Identity key file (ephemeral if empty)")
	relayURI := fs.String("relay", "", "Relay URI (uses hint from ID if empty)")
	fs.Parse(args)

	targetID := *targetIDFlag
	if targetID == "" {
		if fs.NArg() > 0 {
			targetID = fs.Arg(0)
		} else {
			fmt.Fprintln(os.Stderr, "Error: target Device ID is required")
			os.Exit(1)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var identity tunnel.Identity
	var err error
	if *identityFile != "" {
		identity, err = tunnel.LoadOrGenerateIdentity(*identityFile)
		if err != nil {
			logging.Fatal("Failed to load identity: %v", err)
		}
	} else {
		identity = tunnel.GenerateIdentity()
	}

	logging.Banner("RELAY TUNNEL CLIENT")
	logging.Field("Client ID", identity.CompactID)
	logging.Field("Target", targetID)
	logging.Field("Listen", *listenAddr)
	logging.Blank()

	client, err := tunnel.NewClient(tunnel.ClientConfig{
		Identity:   identity,
		TargetID:   targetID,
		RelayURI:   *relayURI,
		ListenAddr: *listenAddr,
		OnTunnelEstablished: func() {
			logging.OK("Tunnel ready! Connect to %s", *listenAddr)
		},
		OnTunnelLost: func(err error) {
			logging.Warn("Tunnel lost: %v (reconnecting...)", err)
		},
		Logger: func(level, msg string) {
			logging.Log(level, msg)
		},
	})
	if err != nil {
		logging.Fatal("Failed to create client: %v", err)
	}

	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		logging.Fatal("Client error: %v", err)
	}
}
