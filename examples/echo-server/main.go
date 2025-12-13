// Echo server for testing tunnel connections
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"
)

var (
	connections int64
	totalBytes  int64
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9999", "Address to listen on")
	mode := flag.String("mode", "echo", "Mode: echo, uppercase, timestamp, discard")
	verbose := flag.Bool("v", false, "Verbose logging")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `Echo Server - Test service for tunnel connections

USAGE:
    %s [OPTIONS]

DESCRIPTION:
    A simple TCP server for testing tunnel connections. Useful for
    verifying that data flows correctly through the tunnel.

MODES:
    echo       Echo received data back unchanged (default)
    uppercase  Echo received data back in uppercase
    timestamp  Prepend timestamp to echoed data
    discard    Read and discard all data (for throughput testing)

EXAMPLES:
    # Start echo server on default port
    %s

    # Start on custom port with timestamps
    %s -addr 0.0.0.0:8080 -mode timestamp

    # High-performance discard mode
    %s -mode discard -v

TESTING WITH TUNNEL:
    1. Start this echo server:
       %s -addr 127.0.0.1:9999

    2. Start tunnel server forwarding to it:
       tunnel-server -forward 127.0.0.1:9999

    3. Start tunnel client:
       tunnel-client -listen 127.0.0.1:2222 <server-device-id>

    4. Connect through tunnel:
       nc localhost 2222
       # Type messages and see them echoed back

OPTIONS:
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	// Print banner
	fmt.Println()
	fmt.Println("╔════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                      ECHO SERVER                               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  %-12s %s\n", "Address:", *addr)
	fmt.Printf("  %-12s %s\n", "Mode:", *mode)
	fmt.Printf("  %-12s %v\n", "Verbose:", *verbose)
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println("  Waiting for connections... (Press Ctrl+C to stop)")
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Println()

	// Stats printer
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				conns := atomic.LoadInt64(&connections)
				bytes := atomic.LoadInt64(&totalBytes)
				log.Printf("📊 Stats: %d active connections, %s total bytes",
					conns, formatBytes(bytes))
			}
		}
	}()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		atomic.AddInt64(&connections, 1)
		connID := atomic.LoadInt64(&connections)

		if *verbose {
			log.Printf("✓ Connection #%d from %s", connID, conn.RemoteAddr())
		}

		go handleConnection(conn, *mode, *verbose, connID)
	}

	// Final stats
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────────")
	fmt.Printf("  Total connections: %d\n", atomic.LoadInt64(&connections))
	fmt.Printf("  Total bytes:       %s\n", formatBytes(atomic.LoadInt64(&totalBytes)))
	fmt.Println("───────────────────────────────────────────────────────────────────")
}

func handleConnection(conn net.Conn, mode string, verbose bool, connID int64) {
	defer func() {
		conn.Close()
		atomic.AddInt64(&connections, -1)
		if verbose {
			log.Printf("○ Connection #%d closed", connID)
		}
	}()

	switch mode {
	case "discard":
		handleDiscard(conn)
	case "uppercase":
		handleUppercase(conn, verbose)
	case "timestamp":
		handleTimestamp(conn, verbose)
	default:
		handleEcho(conn, verbose)
	}
}

func handleEcho(conn net.Conn, verbose bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		atomic.AddInt64(&totalBytes, int64(n))

		if verbose {
			log.Printf("← Recv: %q", truncate(buf[:n], 100))
		}

		_, err = conn.Write(buf[:n])
		if err != nil {
			return
		}

		if verbose {
			log.Printf("→ Sent: %q", truncate(buf[:n], 100))
		}
	}
}

func handleUppercase(conn net.Conn, verbose bool) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		atomic.AddInt64(&totalBytes, int64(len(line)))

		upper := strings.ToUpper(line)
		conn.Write([]byte(upper))

		if verbose {
			log.Printf("← %q → %q", strings.TrimSpace(line), strings.TrimSpace(upper))
		}
	}
}

func handleTimestamp(conn net.Conn, verbose bool) {
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		atomic.AddInt64(&totalBytes, int64(len(line)))

		ts := time.Now().Format("15:04:05.000")
		response := fmt.Sprintf("[%s] %s", ts, line)
		conn.Write([]byte(response))

		if verbose {
			log.Printf("← %q", strings.TrimSpace(line))
		}
	}
}

func handleDiscard(conn net.Conn) {
	written, _ := io.Copy(io.Discard, conn)
	atomic.AddInt64(&totalBytes, written)
}

func truncate(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	return append(b[:max-3], '.', '.', '.')
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
