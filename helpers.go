package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"tunnel/pkg/relay"
	"tunnel/pkg/security"
)

func parseRelayURI(uri string) (addr string, deviceID string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", err
	}

	deviceID = security.NormalizeID(u.Query().Get("id"))
	if deviceID == "" {
		return "", "", fmt.Errorf("relay URI missing device ID")
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", "", fmt.Errorf("invalid relay host: %w", err)
	}

	// Resolve hostname to IP for caching
	ips, err := net.LookupIP(host)
	if err != nil {
		return u.Host, deviceID, nil
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			return net.JoinHostPort(ip.String(), port), deviceID, nil
		}
	}
	if len(ips) > 0 {
		return net.JoinHostPort(ips[0].String(), port), deviceID, nil
	}

	return u.Host, deviceID, nil
}

func formatDeviceIDShort(raw []byte) string {
	if len(raw) < 4 {
		return fmt.Sprintf("%x", raw)
	}
	return fmt.Sprintf("%X...", raw[:4])
}

func defaultYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.AcceptBacklog = 256
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	cfg.MaxStreamWindowSize = 256 * 1024
	cfg.StreamOpenTimeout = 75 * time.Second
	cfg.StreamCloseTimeout = 5 * time.Minute
	cfg.LogOutput = io.Discard
	return cfg
}

// discoverRelay finds the fastest available relay with progress logging.
// Uses default (thorough) options for precise relay selection.
func discoverRelay(ctx context.Context, logger func(level, msg string)) (string, error) {
	opts := relay.DefaultOptions()

	// Track state for intelligent logging
	var (
		mu          sync.Mutex
		lastLogTime time.Time
		bestRelay   *relay.Relay
		startTime   = time.Now()
	)

	if logger != nil {
		opts.OnFetchStart = func() {
			logger("info", "Fetching relay list from Syncthing pool...")
		}

		opts.OnFetchComplete = func(count int) {
			logger("info", fmt.Sprintf("Found %d relays, testing connectivity...", count))
		}

		opts.OnBestSoFar = func(r relay.Relay, tested int) {
			mu.Lock()
			defer mu.Unlock()

			now := time.Now()

			// Log if: first result, significantly better, or 1s since last log
			shouldLog := bestRelay == nil ||
				r.Latency < bestRelay.Latency*2/3 ||
				now.Sub(lastLogTime) > 1*time.Second

			if shouldLog {
				logger("info", fmt.Sprintf("Best: %s (%.1fms), %d relays tested",
					r.Host, r.LatencyMS(), tested))
				lastLogTime = now
				bestRelay = &r
			}
		}

		opts.OnEarlyStop = func(r relay.Relay, testedCount int) {
			elapsed := time.Since(startTime)
			logger("ok", fmt.Sprintf("Early stop after %d relays in %.1fs: %s (%.1fms)",
				testedCount, elapsed.Seconds(), r.Host, r.LatencyMS()))
		}
	}

	r, err := relay.FindFastest(ctx, &opts)
	if err != nil {
		return "", fmt.Errorf("relay discovery failed: %w", err)
	}

	if logger != nil {
		logger("ok", fmt.Sprintf("Selected relay %s with latency %.1fms",
			r.Host, r.LatencyMS()))
	}

	return r.URL, nil
}

// Dial creates a single connection through the tunnel to the target server.
// This is useful for one-off connections without running a full listener.
// If RelayURI is not specified, automatically discovers the fastest relay.
func Dial(config ClientConfig) (net.Conn, error) {
	return DialContext(context.Background(), config)
}

// DialContext creates a single connection through the tunnel with context support.
func DialContext(ctx context.Context, config ClientConfig) (net.Conn, error) {
	config.setDefaults()

	// Auto-discover relay if not specified
	if config.RelayURI == "" {
		uri, err := discoverRelay(ctx, config.Logger)
		if err != nil {
			return nil, err
		}
		config.RelayURI = uri
	}

	client, err := NewClient(config)
	if err != nil {
		return nil, err
	}

	session, err := client.getSession(ctx)
	if err != nil {
		return nil, err
	}

	return session.Open()
}

// BytesToDeviceID converts raw 32-byte device ID to Syncthing format
func BytesToDeviceID(raw []byte) string {
	return security.BytesToDeviceID(raw)
}

// BytesToCompactID converts raw 32-byte device ID to compact format (no dashes)
func BytesToCompactID(raw []byte) string {
	return security.BytesToCompactID(raw)
}

// FindFastestRelay discovers available Syncthing relays and returns the URI
// of the fastest one based on TCP+TLS handshake latency.
//
// This function queries the public Syncthing relay pool, tests connectivity
// to each relay concurrently with multiple probes, and returns the one with
// the lowest latency. Results are cached for 5 minutes.
//
// Example:
//
//	uri, err := tunnel.FindFastestRelay(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	client, _ := tunnel.NewClient(tunnel.ClientConfig{
//	    RelayURI: uri,
//	    // ...
//	})
func FindFastestRelay(ctx context.Context) (string, error) {
	r, err := relay.FindFastest(ctx, nil)
	if err != nil {
		return "", err
	}
	return r.URL, nil
}

// FindFastestRelayFast discovers relays using optimized settings for speed.
// Uses single probe and early termination for faster results.
func FindFastestRelayFast(ctx context.Context) (string, error) {
	opts := relay.FastOptions()
	r, err := relay.FindFastest(ctx, &opts)
	if err != nil {
		return "", err
	}
	return r.URL, nil
}

// FindFastestRelays discovers available Syncthing relays and returns URIs
// of the N fastest ones based on TCP+TLS handshake latency.
//
// This is useful if you want fallback relays or want to let users choose.
func FindFastestRelays(ctx context.Context, n int) ([]string, error) {
	results, err := relay.FindFastestN(ctx, n, nil)
	if err != nil {
		return nil, err
	}
	uris := make([]string, len(results))
	for i, r := range results {
		uris[i] = r.URL
	}
	return uris, nil
}

// FindFastestRelayWithOptions discovers relays with custom options.
// Returns the relay struct with full metadata including latency.
func FindFastestRelayWithOptions(ctx context.Context, opts *relay.Options) (*relay.Relay, error) {
	return relay.FindFastest(ctx, opts)
}

// DiscoverRelays fetches the list of all available relays from the
// Syncthing relay pool without testing them.
func DiscoverRelays(ctx context.Context) ([]relay.Relay, error) {
	return relay.Discover(ctx)
}

// ClearRelayCache clears the cached fastest relay, forcing re-discovery
// on the next connection.
func ClearRelayCache() {
	relay.ClearCache()
}
