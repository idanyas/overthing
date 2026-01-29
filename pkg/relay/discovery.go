package relay

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/idanyas/overthing/pkg/security"
)

const (
	// DiscoveryURL is the Syncthing relay discovery endpoint
	DiscoveryURL = "https://relays.syncthing.net/endpoint/full"

	// DefaultMaxConcurrent is the default number of concurrent latency tests
	DefaultMaxConcurrent = 200

	// DefaultTestTimeout is the default timeout for each relay test
	DefaultTestTimeout = 1200 * time.Millisecond

	// DefaultProbesPerRelay is the number of probes for precise latency measurement
	DefaultProbesPerRelay = 3

	// FastMaxConcurrent allows more parallelism for quick discovery
	FastMaxConcurrent = 300

	// FastTestTimeout is the timeout for quick discovery
	FastTestTimeout = 1000 * time.Millisecond

	// FastProbesPerRelay is the number of probes for quick discovery
	FastProbesPerRelay = 1

	// FastEarlyTerminateLatency stops testing when finding a relay this fast
	// Only triggers after MinTestedBeforeEarlyStop relays AND MinTestDuration
	FastEarlyTerminateLatency = 25 * time.Millisecond

	// FastMinTestedBeforeEarlyStop ensures we test enough relays before early termination
	FastMinTestedBeforeEarlyStop = 250

	// FastMinTestDuration ensures we test for at least this long before early termination
	FastMinTestDuration = 2 * time.Second
)

// Dialer is a function that matches net.Dialer.DialContext
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Relay represents a Syncthing relay server
type Relay struct {
	URL      string        `json:"url"`
	ID       string        `json:"id"`
	Host     string        `json:"host"`
	Port     string        `json:"port"`
	Latency  time.Duration `json:"latency_ns"`
	Provider string        `json:"provider,omitempty"`
}

// LatencyMS returns latency in milliseconds
func (r *Relay) LatencyMS() float64 {
	return float64(r.Latency) / float64(time.Millisecond)
}

// Options configures the relay discovery process
type Options struct {
	// Dialer is an optional custom dialer for network connections.
	// Used for both discovery (HTTP) and latency testing.
	Dialer Dialer

	// MaxConcurrent is the maximum number of concurrent latency tests
	MaxConcurrent int

	// TestTimeout is the timeout for each individual relay test
	TestTimeout time.Duration

	// ProbesPerRelay is the number of connection probes per relay
	// The minimum latency across all probes is used (reduces jitter noise)
	ProbesPerRelay int

	// TLSCert is an optional TLS certificate to use for testing
	TLSCert *tls.Certificate

	// EarlyTerminateLatency stops testing when a relay below this latency is found
	// AND MinTestedBeforeEarlyStop relays have been tested
	// AND MinTestDuration has elapsed.
	// Set to 0 to disable early termination.
	EarlyTerminateLatency time.Duration

	// MinTestedBeforeEarlyStop is the minimum number of relays that must complete
	// testing before early termination can trigger.
	MinTestedBeforeEarlyStop int

	// MinTestDuration is the minimum time that must elapse before early termination
	// can trigger. This ensures geographically distant relays have time to respond.
	MinTestDuration time.Duration

	// OnFetchStart is called when relay list fetch begins
	OnFetchStart func()

	// OnFetchComplete is called when relay list is fetched with the count
	OnFetchComplete func(count int)

	// OnTestStart is called when testing begins with total relay count
	OnTestStart func(total int)

	// OnProgress is called after each relay is tested
	OnProgress func(tested, total int)

	// OnResult is called when a relay test completes (success or failure)
	OnResult func(relay Relay, err error)

	// OnBestSoFar is called when a new best (lowest latency) relay is found
	OnBestSoFar func(relay Relay, tested int)

	// OnEarlyStop is called when early termination triggers
	// Includes the tested count at the time of termination
	OnEarlyStop func(relay Relay, testedCount int)
}

// DefaultOptions returns options for thorough relay discovery.
func DefaultOptions() Options {
	return Options{
		MaxConcurrent:            DefaultMaxConcurrent,
		TestTimeout:              DefaultTestTimeout,
		ProbesPerRelay:           DefaultProbesPerRelay,
		EarlyTerminateLatency:    0,
		MinTestedBeforeEarlyStop: 0,
		MinTestDuration:          0,
	}
}

// FastOptions returns options for quick relay discovery.
func FastOptions() Options {
	return Options{
		MaxConcurrent:            FastMaxConcurrent,
		TestTimeout:              FastTestTimeout,
		ProbesPerRelay:           FastProbesPerRelay,
		EarlyTerminateLatency:    FastEarlyTerminateLatency,
		MinTestedBeforeEarlyStop: FastMinTestedBeforeEarlyStop,
		MinTestDuration:          FastMinTestDuration,
	}
}

// Global cache for relay discovery results
var (
	cachedRelay     *Relay
	cachedRelayTime time.Time
	cachedRelayMu   sync.RWMutex
	cacheValidFor   = 5 * time.Minute
)

// Discover fetches the list of available relays from the Syncthing endpoint
func Discover(ctx context.Context, dialer Dialer) ([]Relay, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	// If a custom dialer is provided, inject it into the HTTP transport
	if dialer != nil {
		client.Transport = &http.Transport{
			DialContext: dialer,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	req, err := http.NewRequestWithContext(ctx, "GET", DiscoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("User-Agent", "github.com/idanyas/overthing/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch relays: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	// The endpoint returns: { "key": [ {url: "..."}, ... ], ... }
	var data map[string][]struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	var relays []Relay
	seen := make(map[string]bool)

	for _, entries := range data {
		for _, entry := range entries {
			if entry.URL == "" || seen[entry.URL] {
				continue
			}
			seen[entry.URL] = true

			relay, err := ParseURL(entry.URL)
			if err != nil {
				continue
			}
			relays = append(relays, *relay)
		}
	}

	return relays, nil
}

// ParseURL parses a relay URL and extracts its components
func ParseURL(rawURL string) (*Relay, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "relay" {
		return nil, fmt.Errorf("invalid scheme: %s", u.Scheme)
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, err
	}

	id := u.Query().Get("id")
	if id == "" {
		return nil, fmt.Errorf("missing relay ID")
	}

	provider := u.Query().Get("providedBy")

	return &Relay{
		URL:      rawURL,
		ID:       security.NormalizeID(id),
		Host:     host,
		Port:     port,
		Provider: provider,
	}, nil
}

// probeLatency does a single TCP+TLS probe and returns the latency
func probeLatency(ctx context.Context, addr string, relayID string, tlsCert *tls.Certificate, dialer Dialer) (time.Duration, error) {
	start := time.Now()

	var conn net.Conn
	var err error

	if dialer != nil {
		conn, err = dialer(ctx, "tcp", addr)
	} else {
		d := &net.Dialer{}
		conn, err = d.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"bep-relay"},
		MinVersion:         tls.VersionTLS13,
	}
	if tlsCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*tlsCert}
	}

	tlsConn := tls.Client(conn, tlsConfig)

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(5 * time.Second)
	}
	tlsConn.SetDeadline(deadline)

	if err := tlsConn.Handshake(); err != nil {
		return 0, fmt.Errorf("tls: %w", err)
	}

	// Verify relay ID
	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return 0, fmt.Errorf("no peer certificates")
	}

	remoteID := security.NormalizeID(security.GetDeviceID(peerCerts[0].Raw))
	if remoteID != relayID {
		return 0, fmt.Errorf("ID mismatch")
	}

	return time.Since(start), nil
}

// TestLatency tests the connection latency to a relay with multiple probes.
func TestLatency(ctx context.Context, r *Relay, opts *Options) error {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	probes := opts.ProbesPerRelay
	if probes < 1 {
		probes = 1
	}

	addr := net.JoinHostPort(r.Host, r.Port)

	// Optimization: Pre-resolve IP if NO custom dialer is present.
	// If a custom dialer is present, we cannot assume the default resolver
	// routes correctly, or the dialer might be a proxy requiring hostnames.
	if opts.Dialer == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", r.Host)
		if err == nil {
			var targetIP string
			for _, ip := range ips {
				if ip.To4() != nil {
					targetIP = ip.String()
					break
				}
			}
			if targetIP == "" && len(ips) > 0 {
				targetIP = ips[0].String()
			}
			if targetIP != "" {
				addr = net.JoinHostPort(targetIP, r.Port)
			}
		}
	}

	var minLatency time.Duration

	for i := 0; i < probes; i++ {
		if ctx.Err() != nil {
			if minLatency > 0 {
				break
			}
			return ctx.Err()
		}

		probeCtx, cancel := context.WithTimeout(ctx, opts.TestTimeout)
		latency, err := probeLatency(probeCtx, addr, r.ID, opts.TLSCert, opts.Dialer)
		cancel()

		if err != nil {
			if i == 0 {
				return err
			}
			continue
		}

		if minLatency == 0 || latency < minLatency {
			minLatency = latency
		}
	}

	if minLatency == 0 {
		return fmt.Errorf("all probes failed")
	}

	r.Latency = minLatency

	return nil
}

// FindFastest discovers relays and returns the one with lowest latency.
func FindFastest(ctx context.Context, opts *Options) (*Relay, error) {
	// Check cache first (only if no custom dialer, as dialers might change context)
	if opts == nil || opts.Dialer == nil {
		cachedRelayMu.RLock()
		if cachedRelay != nil && time.Since(cachedRelayTime) < cacheValidFor {
			r := *cachedRelay
			cachedRelayMu.RUnlock()
			return &r, nil
		}
		cachedRelayMu.RUnlock()
	}

	results, err := FindFastestN(ctx, 1, opts)
	if err != nil {
		return nil, err
	}

	// Update cache (only if default dialer)
	if opts == nil || opts.Dialer == nil {
		cachedRelayMu.Lock()
		cachedRelay = &results[0]
		cachedRelayTime = time.Now()
		cachedRelayMu.Unlock()
	}

	return &results[0], nil
}

// FindFastestN discovers relays and returns the N fastest
func FindFastestN(ctx context.Context, n int, opts *Options) ([]Relay, error) {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	if opts.OnFetchStart != nil {
		opts.OnFetchStart()
	}

	relays, err := Discover(ctx, opts.Dialer)
	if err != nil {
		return nil, err
	}

	if opts.OnFetchComplete != nil {
		opts.OnFetchComplete(len(relays))
	}

	return TestAllAndSort(ctx, relays, n, opts)
}

// TestAllAndSort tests all provided relays and returns up to n fastest ones.
func TestAllAndSort(ctx context.Context, relays []Relay, n int, opts *Options) ([]Relay, error) {
	if opts == nil {
		defaultOpts := DefaultOptions()
		opts = &defaultOpts
	}

	if len(relays) == 0 {
		return nil, fmt.Errorf("no relays to test")
	}

	maxConcurrent := opts.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = DefaultMaxConcurrent
	}

	testCtx, cancelTest := context.WithCancel(ctx)
	defer cancelTest()

	startTime := time.Now()

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrent)

	var mu sync.Mutex
	var available []Relay
	var bestRelay *Relay
	var bestLatency time.Duration

	var tested int32
	var stopped int32

	if opts.OnTestStart != nil {
		opts.OnTestStart(len(relays))
	}

	for i := range relays {
		relay := relays[i]
		wg.Add(1)

		go func(r Relay) {
			defer wg.Done()

			if atomic.LoadInt32(&stopped) != 0 {
				return
			}

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-testCtx.Done():
				return
			}

			if atomic.LoadInt32(&stopped) != 0 {
				return
			}

			testErr := TestLatency(testCtx, &r, opts)
			testedCount := int(atomic.AddInt32(&tested, 1))

			mu.Lock()

			if testErr == nil {
				available = append(available, r)

				if bestRelay == nil || r.Latency < bestLatency {
					bestLatency = r.Latency
					rCopy := r
					bestRelay = &rCopy

					if opts.OnBestSoFar != nil {
						opts.OnBestSoFar(r, testedCount)
					}
				}
			}

			if opts.OnProgress != nil {
				opts.OnProgress(testedCount, len(relays))
			}

			if opts.OnResult != nil {
				opts.OnResult(r, testErr)
			}

			if opts.EarlyTerminateLatency > 0 &&
				testedCount >= opts.MinTestedBeforeEarlyStop &&
				time.Since(startTime) >= opts.MinTestDuration &&
				bestRelay != nil &&
				bestLatency <= opts.EarlyTerminateLatency &&
				atomic.CompareAndSwapInt32(&stopped, 0, 1) {

				if opts.OnEarlyStop != nil {
					opts.OnEarlyStop(*bestRelay, testedCount)
				}
				cancelTest()
			}

			mu.Unlock()
		}(relay)
	}

	wg.Wait()

	if ctx.Err() != nil && atomic.LoadInt32(&stopped) == 0 {
		return nil, ctx.Err()
	}

	if len(available) == 0 {
		return nil, fmt.Errorf("no available relays (tested %d)", atomic.LoadInt32(&tested))
	}

	sort.Slice(available, func(i, j int) bool {
		return available[i].Latency < available[j].Latency
	})

	if n <= 0 || n > len(available) {
		n = len(available)
	}

	return available[:n], nil
}

func ClearCache() {
	cachedRelayMu.Lock()
	cachedRelay = nil
	cachedRelayMu.Unlock()
}
