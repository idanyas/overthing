// One-shot connection through tunnel with detailed progress
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/idanyas/overthing"
)

func main() {
	relayURI := flag.String("relay", "", "Relay URI (auto-discover if empty)")
	timeout := flag.Duration("timeout", 30*time.Second, "Connection timeout")
	readTimeout := flag.Duration("read-timeout", 10*time.Second, "Read timeout after connect")
	message := flag.String("message", "Hello through the tunnel!\n", "Message to send")
	verbose := flag.Bool("v", false, "Verbose output")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Tunnel Dial - One-shot connection through a tunnel

USAGE:
    %s [OPTIONS] <server-device-id>

DESCRIPTION:
    Establishes a single connection through a tunnel to the target server,
    sends a message, reads the response, and exits. Useful for testing
    and scripting.

EXAMPLES:
    # Simple test connection
    %s <device-id>

    # Send custom message
    %s -message "GET / HTTP/1.0\r\n\r\n" <device-id>

    # With timeout settings
    %s -timeout 60s -read-timeout 30s <device-id>

OPTIONS:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}
	serverID := flag.Arg(0)

	// Create ephemeral identity
	identity := tunnel.GenerateIdentity()
	
	fmt.Println()
	fmt.Println("TUNNEL DIAL")
	fmt.Println("───────────────────────────────────────────────")
	fmt.Printf("  Client ID:  %s\n", identity.CompactID)
	fmt.Printf("  Target:     %s\n", truncateID(serverID, 45))
	fmt.Printf("  Timeout:    %s\n", *timeout)
	fmt.Println("───────────────────────────────────────────────")
	fmt.Println()

	start := time.Now()
	fmt.Println("⏳ Connecting...")

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	var lastLog time.Time
	conn, err := tunnel.DialContext(ctx, tunnel.ClientConfig{
		Identity: identity,
		TargetID: serverID,
		RelayURI: *relayURI,
		Logger: func(level, msg string) {
			if *verbose || level == "ok" || level == "error" {
				if time.Since(lastLog) > 100*time.Millisecond {
					fmt.Printf("   %s: %s\n", level, msg)
					lastLog = time.Now()
				}
			}
		},
	})
	if err != nil {
		fmt.Printf("✗ Connection failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	connectTime := time.Since(start)
	fmt.Printf("✓ Connected in %s\n", connectTime.Round(time.Millisecond))
	fmt.Println()

	// Send message
	fmt.Printf("→ Sending: %q\n", *message)
	n, err := conn.Write([]byte(*message))
	if err != nil {
		log.Printf("Write error: %v", err)
	} else {
		fmt.Printf("  Sent %d bytes\n", n)
	}

	// Read response
	fmt.Println()
	fmt.Println("← Reading response...")
	
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(*readTimeout))
	
	totalRead := 0
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			totalRead += n
			fmt.Printf("%s", buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("\n  (Read ended: %v)\n", err)
			}
			break
		}
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────")
	fmt.Printf("  Connect time: %s\n", connectTime.Round(time.Millisecond))
	fmt.Printf("  Bytes sent:   %d\n", len(*message))
	fmt.Printf("  Bytes recv:   %d\n", totalRead)
	fmt.Println("───────────────────────────────────────────────")
}

func truncateID(id string, maxLen int) string {
	if len(id) <= maxLen {
		return id
	}
	return id[:maxLen-3] + "..."
}
