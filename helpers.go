package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/idanyas/overthing/pkg/relay"
	"github.com/idanyas/overthing/pkg/security"
)

func parseRelayURI(uri string) (addr string, deviceID string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", "", err
	}

	idParam := u.Query().Get("id")
	if idParam != "" {
		deviceID = security.NormalizeID(idParam)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", "", fmt.Errorf("invalid relay host: %w", err)
	}

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
	cfg.EnableKeepAlive = false
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.ConnectionWriteTimeout = 10 * time.Second
	// 4MB Window: Prevents throughput collapse on high-latency links.
	cfg.MaxStreamWindowSize = 4 * 1024 * 1024
	cfg.StreamOpenTimeout = 15 * time.Second
	cfg.StreamCloseTimeout = 30 * time.Second
	cfg.LogOutput = io.Discard
	return cfg
}

func discoverRelay(ctx context.Context, logger func(level, msg string), dialer func(context.Context, string, string) (net.Conn, error), ignore map[string]bool) (string, error) {
	opts := relay.FastOptions()
	opts.Dialer = dialer

	if logger != nil {
		opts.OnFetchStart = func() {
			logger("info", "Fetching relay list from Syncthing pool...")
		}
		opts.OnFetchComplete = func(count int) {
			logger("info", fmt.Sprintf("Found %d relays, testing for fastest...", count))
		}
	}

	results, err := relay.FindFastestN(ctx, 5, &opts)
	if err != nil {
		return "", fmt.Errorf("relay discovery failed: %w", err)
	}

	var selected *relay.Relay

	for i := range results {
		r := &results[i]
		if ignore != nil && ignore[r.URL] {
			if logger != nil {
				logger("info", fmt.Sprintf("Skipping ignored relay: %s (%.1fms)", r.Host, r.LatencyMS()))
			}
			continue
		}
		selected = r
		break
	}

	if selected == nil {
		return "", fmt.Errorf("no suitable relays found (checked top %d)", len(results))
	}

	if logger != nil {
		addr := net.JoinHostPort(selected.Host, selected.Port)
		logger("ok", fmt.Sprintf("Selected relay: %s (%.1fms)", addr, selected.LatencyMS()))
	}

	return selected.URL, nil
}

func Dial(config ClientConfig) (net.Conn, error) {
	return DialContext(context.Background(), config)
}

func DialContext(ctx context.Context, config ClientConfig) (net.Conn, error) {
	config.setDefaults()

	if config.RelayURI == "" {
		uri, err := discoverRelay(ctx, config.Logger, config.Dialer, nil)
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
