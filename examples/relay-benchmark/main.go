// Relay benchmark - discovers and tests all Syncthing relays
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/idanyas/overthing/pkg/relay"
)

func main() {
	top := flag.Int("top", 10, "Number of top relays to show")
	timeout := flag.Duration("timeout", 3*time.Second, "Timeout per relay test")
	concurrent := flag.Int("concurrent", 200, "Max concurrent tests")
	probes := flag.Int("probes", 2, "Number of probes per relay")
	showAll := flag.Bool("all", false, "Show all available relays")
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	quiet := flag.Bool("q", false, "Quiet mode - only output the fastest relay URI")
	fast := flag.Bool("fast", false, "Fast mode - 1 probe, early termination")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if !*quiet && !*jsonOutput {
		fmt.Fprintln(os.Stderr, "Discovering Syncthing relays...")
	}

	relays, err := relay.Discover(ctx, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !*quiet && !*jsonOutput {
		fmt.Fprintf(os.Stderr, "Found %d relays, testing...\n", len(relays))
	}

	n := *top
	if *showAll {
		n = 0
	}

	var opts *relay.Options
	if *fast {
		fastOpts := relay.FastOptions()
		opts = &fastOpts
	} else {
		opts = &relay.Options{
			MaxConcurrent:  *concurrent,
			TestTimeout:    *timeout,
			ProbesPerRelay: *probes,
		}
	}

	if !*quiet && !*jsonOutput {
		startTime := time.Now()
		opts.OnProgress = func(tested, total int) {
			elapsed := time.Since(startTime)
			pct := float64(tested) / float64(total) * 100
			fmt.Fprintf(os.Stderr, "\rTesting: %d/%d (%.0f%%) [%.1fs]", tested, total, pct, elapsed.Seconds())
		}
		opts.OnBestSoFar = func(r relay.Relay, tested int) {
			fmt.Fprintf(os.Stderr, "\rBest so far: %s (%.1fms) after %d tests\n", r.Host, r.LatencyMS(), tested)
		}
		if *fast {
			opts.OnEarlyStop = func(r relay.Relay, testedCount int) {
				fmt.Fprintf(os.Stderr, "\rEarly stop after %d relays: %s (%.1fms)\n", testedCount, r.Host, r.LatencyMS())
			}
		}
	}

	results, err := relay.TestAllAndSort(ctx, relays, n, opts)

	if !*quiet && !*jsonOutput {
		fmt.Fprintln(os.Stderr)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if *quiet {
		if len(results) > 0 {
			fmt.Println(results[0].URL)
		}
		return
	}

	if *jsonOutput {
		printJSON(results)
		return
	}

	fmt.Printf("\nTop %d fastest relays (of %d available):\n\n", len(results), len(relays))

	maxHostLen := 22
	for _, r := range results {
		hostPort := r.Host + ":" + r.Port
		if len(hostPort) > maxHostLen {
			maxHostLen = len(hostPort)
		}
	}
	if maxHostLen > 40 {
		maxHostLen = 40
	}

	fmt.Printf("%-8s  %-*s  %s\n", "LATENCY", maxHostLen, "HOST", "PROVIDER")
	fmt.Printf("%-8s  %-*s  %s\n", strings.Repeat("-", 7), maxHostLen, strings.Repeat("-", maxHostLen), strings.Repeat("-", 8))

	for _, r := range results {
		provider := r.Provider
		if provider == "" {
			provider = "-"
		}
		provider = decodeProvider(provider)
		if len(provider) > 50 {
			provider = provider[:47] + "..."
		}

		hostPort := r.Host + ":" + r.Port
		if len(hostPort) > maxHostLen {
			hostPort = hostPort[:maxHostLen-3] + "..."
		}

		fmt.Printf("%6.1fms  %-*s  %s\n", r.LatencyMS(), maxHostLen, hostPort, provider)
	}

	if len(results) > 0 {
		fmt.Printf("\n%s\n", strings.Repeat("=", 60))
		fmt.Printf("Fastest relay:\n%s\n", results[0].URL)
	}
}

func decodeProvider(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	s = strings.ReplaceAll(s, "%7C", "|")
	s = strings.ReplaceAll(s, "%20", " ")
	return s
}

func printJSON(relays []relay.Relay) {
	fmt.Println("[")
	for i, r := range relays {
		comma := ","
		if i == len(relays)-1 {
			comma = ""
		}
		fmt.Printf(`  {"url": %q, "host": %q, "latency_ms": %.2f, "provider": %q}%s`+"\n",
			r.URL, r.Host+":"+r.Port, r.LatencyMS(), r.Provider, comma)
	}
	fmt.Println("]")
}
