// One-shot connection through tunnel (auto-discovers relay)
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"tunnel"
)

func main() {
	relayURI := flag.String("relay", "", "Relay URI (auto-discover if empty)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <server-device-id>\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}
	serverID := flag.Arg(0)

	identity := tunnel.GenerateIdentity()
	log.Printf("Using ephemeral identity: %s", identity.CompactID)

	log.Println("Connecting...")
	conn, err := tunnel.Dial(tunnel.ClientConfig{
		Identity: identity,
		TargetID: serverID,
		RelayURI: *relayURI,
		Logger: func(level, msg string) {
			log.Printf("[%s] %s", level, msg)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	log.Println("Connected through tunnel!")

	conn.Write([]byte("Hello through the tunnel!\n"))

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Read error: %v", err)
	}
	if n > 0 {
		fmt.Printf("Response: %s\n", buf[:n])
	}
}
