package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/idanyas/overthing/pkg/network"
	"github.com/idanyas/overthing/pkg/protocol"
	"github.com/idanyas/overthing/pkg/relay"
	"github.com/idanyas/overthing/pkg/security"
)

// Package-level cache
var (
	relayCache      []relay.Relay
	relayCacheTime  time.Time
	relayCacheMu    sync.RWMutex
	relayCacheTTL   = 15 * time.Minute
)

type Client struct {
	config      ClientConfig
	tlsConfig   *tls.Config
	targetBytes []byte

	relayAddr    string
	relayID      string
	isFixedRelay bool

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	listener net.Listener

	muxMu      sync.RWMutex
	session    *yamux.Session
	bepConn    *tls.Conn
	sessionGen uint64
}

func NewClient(config ClientConfig) (*Client, error) {
	config.setDefaults()

	cleanID, hintIP, hintPort, hasHint := security.SplitRelayHint(config.TargetID)
	config.TargetID = cleanID

	targetBytes, err := security.DeviceIDFromString(config.TargetID)
	if err != nil {
		return nil, fmt.Errorf("invalid target device ID: %w", err)
	}

	isFixedRelay := false

	if config.RelayURI != "" {
		isFixedRelay = true
		if config.Logger != nil {
			config.Logger("info", fmt.Sprintf("Using configured relay: %s", config.RelayURI))
		}
	} else if hasHint {
		config.RelayURI = fmt.Sprintf("relay://%s", net.JoinHostPort(hintIP.String(), fmt.Sprintf("%d", hintPort)))
		if config.Logger != nil {
			config.Logger("ok", fmt.Sprintf("Extracted relay hint: %s", config.RelayURI))
		}
	} else {
		if config.Logger != nil {
			config.Logger("info", "No relay hint. Will scan network for target.")
		}
	}

	var relayAddr, relayID string
	if config.RelayURI != "" {
		relayAddr, relayID, err = parseRelayURI(config.RelayURI)
		if err != nil {
			return nil, fmt.Errorf("invalid relay URI: %w", err)
		}
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{config.Identity.Certificate},
		InsecureSkipVerify: true,
		NextProtos:         []string{"bep-relay"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	return &Client{
		config:       config,
		tlsConfig:    tlsConfig,
		targetBytes:  targetBytes,
		relayAddr:    relayAddr,
		relayID:      relayID,
		isFixedRelay: isFixedRelay,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return errors.New("client already running")
	}
	c.running = true
	ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.running = false
		c.mu.Unlock()
	}()

	var listener net.Listener
	var err error

	if c.config.Listener != nil {
		listener = c.config.Listener
		c.log("ok", fmt.Sprintf("Listening on %s", listener.Addr()))
	} else {
		listener, err = net.Listen("tcp", c.config.ListenAddr)
		if err != nil {
			return fmt.Errorf("listen failed: %w", err)
		}
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			network.EnableTCPFastOpen(tcpListener)
		}
		c.log("ok", fmt.Sprintf("Listening on %s", c.config.ListenAddr))
	}

	c.listener = listener
	defer listener.Close()

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	// Automatic Connectivity Maintenance in background
	go func() {
		c.log("info", "Verifying connectivity to server...")

		delay := c.config.ReconnectDelay
		if delay < 1*time.Second {
			delay = 1 * time.Second
		}

		for {
			if ctx.Err() != nil {
				return
			}

			// We pass the main context here. The establishment logic handles its own timeouts.
			session, err := c.getSession(ctx)

			if err != nil {
				c.log("warn", fmt.Sprintf("Connection failed: %v", err))
				c.log("info", fmt.Sprintf("Retrying in %v...", delay))

				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
					// Exponential backoff with cap
					if delay < 30*time.Second {
						delay *= 2
					}
				}
				continue
			}

			// Connected successfully
			c.log("ok", "Tunnel is ready.")
			
			// Reset delay
			delay = c.config.ReconnectDelay
			if delay < 1*time.Second {
				delay = 1 * time.Second
			}

			// Block until session closes or context cancelled
			select {
			case <-session.CloseChan():
				c.log("warn", "Tunnel connection lost. Reconnecting...")
			case <-ctx.Done():
				return
			}
			
			// Brief pause to prevent hot loops
			time.Sleep(100 * time.Millisecond)
		}
	}()

	for {
		localConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		network.OptimizeConn(localConn)
		go c.handleConnection(ctx, localConn)
	}
}

func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cancel != nil {
		c.cancel()
	}
	if c.listener != nil {
		c.listener.Close()
	}
}

func (c *Client) handleConnection(ctx context.Context, localConn net.Conn) {
	defer localConn.Close()

	var session *yamux.Session
	var sessionGen uint64
	var err error
	var stream net.Conn

	backoff := 100 * time.Millisecond

	for {
		if ctx.Err() != nil {
			return
		}

		session, sessionGen, err = c.getSessionWithGen(ctx)
		if err == nil {
			stream, err = session.Open()
			if err == nil {
				break // Success
			}
			c.invalidateSessionIfMatch(sessionGen)
		}

		if backoff > 2*time.Second {
			c.log("info", fmt.Sprintf("Waiting for tunnel... (%v)", err))
		}
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			if backoff < 2*time.Second {
				backoff *= 2
			}
		}
	}

	defer stream.Close()
	network.CopyBidirectional(stream, localConn)
}

func (c *Client) getSession(ctx context.Context) (*yamux.Session, error) {
	session, _, err := c.getSessionWithGen(ctx)
	return session, err
}

func (c *Client) getSessionWithGen(ctx context.Context) (*yamux.Session, uint64, error) {
	c.muxMu.RLock()
	session := c.session
	gen := c.sessionGen

	if session != nil && !session.IsClosed() {
		c.muxMu.RUnlock()
		return session, gen, nil
	}
	c.muxMu.RUnlock()

	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	if c.session != nil && !c.session.IsClosed() {
		return c.session, c.sessionGen, nil
	}

	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	if c.bepConn != nil {
		c.bepConn.Close()
		c.bepConn = nil
	}

	session, bepConn, err := c.establishNewSession(ctx)
	if err != nil {
		return nil, 0, err
	}

	c.session = session
	c.bepConn = bepConn
	c.sessionGen++

	c.log("ok", "Tunnel established")
	if c.config.OnTunnelEstablished != nil {
		c.config.OnTunnelEstablished()
	}

	return session, c.sessionGen, nil
}

func (c *Client) establishNewSession(ctx context.Context) (*yamux.Session, *tls.Conn, error) {
	if c.config.RelayURI == "" {
		if c.isFixedRelay {
			return nil, nil, errors.New("relay URI missing in fixed configuration")
		}

		c.log("info", "Scanning network for target device...")
		tunnelConn, relayURI, err := c.scanAndConnect(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("discovery failed: %w", err)
		}

		c.config.RelayURI = relayURI
		c.relayAddr, c.relayID, _ = parseRelayURI(relayURI)

		session, bepConn, err := c.completeBEPHandshake(tunnelConn)
		if err != nil {
			tunnelConn.Close()
			return nil, nil, err
		}
		return session, bepConn, nil
	}

	// Connect to known relay
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		tunnelConn, err := c.connectToKnownRelay(ctx)
		if err != nil {
			c.log("warn", fmt.Sprintf("Connection attempt %d failed: %v", attempt+1, err))
			if attempt < 2 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			
			if !c.isFixedRelay {
				c.log("info", "Known relay seems down, re-scanning...")
				c.config.RelayURI = ""
				c.relayAddr = ""
				c.relayID = ""
				return c.establishNewSession(ctx)
			}
			return nil, nil, err
		}

		session, bepConn, err := c.completeBEPHandshake(tunnelConn)
		if err != nil {
			tunnelConn.Close()
			c.log("warn", fmt.Sprintf("Handshake attempt %d failed: %v", attempt+1, err))
			if attempt < 2 {
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return nil, nil, err
		}

		return session, bepConn, nil
	}

	return nil, nil, errors.New("failed to connect")
}

func (c *Client) scanAndConnect(ctx context.Context) (net.Conn, string, error) {
	var relays []relay.Relay
	var err error
	
	// 1. Check Cache
	relayCacheMu.RLock()
	if len(relayCache) > 0 && time.Since(relayCacheTime) < relayCacheTTL {
		relays = make([]relay.Relay, len(relayCache))
		copy(relays, relayCache)
	}
	relayCacheMu.RUnlock()

	// 2. Network Fetch with Retries
	if len(relays) == 0 {
		c.log("info", "Fetching public relay list...")
		
		// Try 3 times, short timeouts, to survive packet loss/DNS blips
		for i := 0; i < 3; i++ {
			fetchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			relays, err = relay.Discover(fetchCtx, relay.Dialer(c.config.Dialer))
			cancel()
			
			if err == nil && len(relays) > 0 {
				break
			}
			if i < 2 {
				time.Sleep(200 * time.Millisecond)
			}
		}

		if err != nil {
			// Fallback to stale cache if available
			relayCacheMu.RLock()
			if len(relayCache) > 0 {
				c.log("warn", "Fetch failed, using stale cache backup.")
				relays = make([]relay.Relay, len(relayCache))
				copy(relays, relayCache)
				err = nil
			}
			relayCacheMu.RUnlock()
		}
		
		if err != nil {
			return nil, "", fmt.Errorf("fetch relays: %w", err)
		}

		relayCacheMu.Lock()
		relayCache = relays
		relayCacheTime = time.Now()
		relayCacheMu.Unlock()
	}

	// 3. Shuffle
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	rng.Shuffle(len(relays), func(i, j int) {
		relays[i], relays[j] = relays[j], relays[i]
	})

	c.log("info", fmt.Sprintf("Scanning %d relays for device %x...", len(relays), c.targetBytes[:4]))

	type result struct {
		conn     net.Conn
		relayURI string
	}

	results := make(chan result, 1)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	var found int32
	var errCountDial int32
	var errCountTLS int32
	var errCountNotFound int32
	var errCountOther int32
	
	// FIX: Conservative tuning for First Attempt Success
	// Concurrency: 50 (Low enough to prevent Router/OS table exhaustion)
	// Pacing: 20ms (Prevents SYN flood detection)
	// Timeout: 2.5s (Sufficient for global latency)
	concurrency := 50
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, r := range relays {
		if atomic.LoadInt32(&found) != 0 {
			break
		}

		wg.Add(1)
		
		// Pacer: 20ms
		time.Sleep(20 * time.Millisecond)

		go func(r relay.Relay) {
			defer wg.Done()
			
			select {
			case sem <- struct{}{}:
			case <-scanCtx.Done():
				return
			}
			defer func() { <-sem }()

			if atomic.LoadInt32(&found) != 0 {
				return
			}

			// Dial Timeout: 2.5s 
			probeCtx, cancel := context.WithTimeout(scanCtx, 2500*time.Millisecond)
			defer cancel()

			conn, err := c.tryRelayAndConnect(probeCtx, r)
			if err != nil {
				// Diagnostic counting
				msg := err.Error()
				if strings.Contains(msg, "dial") || strings.Contains(msg, "timeout") {
					atomic.AddInt32(&errCountDial, 1)
				} else if strings.Contains(msg, "tls") || strings.Contains(msg, "certificate") {
					atomic.AddInt32(&errCountTLS, 1)
				} else if strings.Contains(msg, "target not found") {
					atomic.AddInt32(&errCountNotFound, 1)
				} else {
					atomic.AddInt32(&errCountOther, 1)
				}
				return
			}

			if atomic.CompareAndSwapInt32(&found, 0, 1) {
				select {
				case results <- result{conn: conn, relayURI: r.URL}:
					scanCancel()
				default:
					conn.Close()
				}
			} else {
				conn.Close()
			}
		}(r)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	select {
	case res, ok := <-results:
		if !ok {
			// SCAN FAILED - Log detailed diagnostics
			c.log("warn", fmt.Sprintf("Scan Stats | Dial/Net Fail: %d | Not Found: %d | TLS/Other: %d", 
				atomic.LoadInt32(&errCountDial), 
				atomic.LoadInt32(&errCountNotFound),
				atomic.LoadInt32(&errCountTLS) + atomic.LoadInt32(&errCountOther)))
				
			return nil, "", errors.New("target device not found on any relay")
		}
		u, _ := url.Parse(res.relayURI)
		c.log("ok", fmt.Sprintf("Found device on relay: %s", u.Host))
		return res.conn, res.relayURI, nil
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

func (c *Client) tryRelayAndConnect(ctx context.Context, r relay.Relay) (net.Conn, error) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	addr := net.JoinHostPort(r.Host, r.Port)

	// Stage 1: TCP Dial
	var conn net.Conn
	
	if c.config.Dialer != nil {
		conn, err = c.config.Dialer(ctx, "tcp", addr)
	} else {
		// Use specific timeout for TCP connection too (matched to probe timeout)
		d := &net.Dialer{Timeout: 2500 * time.Millisecond}
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	network.OptimizeConn(conn)

	// Set deadline for the rest of the handshake
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	
	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.ServerName = host

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	// Stage 2: Negotiation
	if err := protocol.WriteMessage(tlsConn, protocol.MsgJoinRelayRequest, []byte{0, 0, 0, 0}); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Read Join Response
	gotJoin := false
	for !gotJoin {
		msgType, body, err := protocol.ReadMessage(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}
		if msgType == protocol.MsgPing {
			protocol.WriteMessage(tlsConn, protocol.MsgPong, nil)
			continue
		}
		if msgType == protocol.MsgResponse {
			if len(body) >= 4 {
				code := int32(binary.BigEndian.Uint32(body[:4]))
				if code != 0 {
					tlsConn.Close()
					return nil, fmt.Errorf("join rejected: code %d", code)
				}
			}
			gotJoin = true
			break
		}
		tlsConn.Close()
		return nil, errors.New("unexpected message")
	}

	if err := protocol.WriteMessage(tlsConn, protocol.MsgConnectRequest, protocol.XDRBytes(c.targetBytes)); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Wait for invitation
	for {
		msgType, body, err := protocol.ReadMessage(tlsConn)
		if err != nil {
			tlsConn.Close()
			return nil, err
		}

		if msgType == protocol.MsgPing {
			protocol.WriteMessage(tlsConn, protocol.MsgPong, nil)
			continue
		}

		if msgType == protocol.MsgResponse {
			if len(body) >= 4 {
				if code := int32(binary.BigEndian.Uint32(body[:4])); code != 0 {
					tlsConn.Close()
					return nil, errors.New("target not found")
				}
			}
			continue
		}

		if msgType == protocol.MsgSessionInvitation {
			inv, err := protocol.DecodeInvitation(body)
			if err != nil {
				tlsConn.Close()
				return nil, err
			}

			if len(inv.From) != len(c.targetBytes) {
				continue
			}
			match := true
			for i := range inv.From {
				if inv.From[i] != c.targetBytes[i] {
					match = false
					break
				}
			}
			if !match {
				continue
			}

			tlsConn.Close()

			var sessionAddr string
			if len(inv.Address) > 0 && !net.IP(inv.Address).IsUnspecified() {
				sessionAddr = net.JoinHostPort(net.IP(inv.Address).String(), fmt.Sprintf("%d", inv.Port))
			} else {
				sessionAddr = net.JoinHostPort(host, fmt.Sprintf("%d", inv.Port))
			}

			var sConn net.Conn
			
			// Dial the session
			if c.config.Dialer != nil {
				sConn, err = c.config.Dialer(ctx, "tcp", sessionAddr)
			} else {
				d := &net.Dialer{Timeout: 4 * time.Second}
				sConn, err = d.DialContext(ctx, "tcp", sessionAddr)
			}

			if err != nil {
				return nil, err
			}
			network.OptimizeConn(sConn)

			if err := protocol.WriteMessage(sConn, protocol.MsgJoinSessionRequest, protocol.XDRBytes(inv.Key)); err != nil {
				sConn.Close()
				return nil, err
			}

			sConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			mType, mBody, err := protocol.ReadMessage(sConn)
			sConn.SetReadDeadline(time.Time{})

			if err != nil {
				sConn.Close()
				return nil, err
			}

			if mType != protocol.MsgResponse {
				sConn.Close()
				return nil, errors.New("unexpected response")
			}

			if len(mBody) >= 4 {
				if code := int32(binary.BigEndian.Uint32(mBody[:4])); code != 0 {
					sConn.Close()
					return nil, fmt.Errorf("session rejected: %d", code)
				}
			}

			return sConn, nil
		}

		tlsConn.Close()
		return nil, errors.New("unexpected message")
	}
}

func (c *Client) connectToKnownRelay(ctx context.Context) (net.Conn, error) {
	relayConn, err := c.connectToRelay(ctx)
	if err != nil {
		return nil, err
	}

	if err := protocol.WriteMessage(relayConn, protocol.MsgConnectRequest, protocol.XDRBytes(c.targetBytes)); err != nil {
		relayConn.Close()
		return nil, err
	}

	for {
		relayConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		msgType, body, err := protocol.ReadMessage(relayConn)
		if err != nil {
			relayConn.Close()
			return nil, err
		}

		if msgType == protocol.MsgPing {
			protocol.WriteMessage(relayConn, protocol.MsgPong, nil)
			continue
		}

		if msgType == protocol.MsgResponse {
			if len(body) >= 4 {
				if code := int32(binary.BigEndian.Uint32(body[:4])); code != 0 {
					relayConn.Close()
					return nil, fmt.Errorf("connect rejected: code %d", code)
				}
			}
			continue
		}

		if msgType == protocol.MsgSessionInvitation {
			inv, err := protocol.DecodeInvitation(body)
			if err != nil {
				relayConn.Close()
				return nil, err
			}

			if len(inv.From) != len(c.targetBytes) {
				continue
			}
			match := true
			for i := range inv.From {
				if inv.From[i] != c.targetBytes[i] {
					match = false
					break
				}
			}
			if !match {
				continue
			}

			relayConn.Close()

			var sessionAddr string
			if len(inv.Address) > 0 && !net.IP(inv.Address).IsUnspecified() {
				sessionAddr = net.JoinHostPort(net.IP(inv.Address).String(), fmt.Sprintf("%d", inv.Port))
			} else {
				host, _, _ := net.SplitHostPort(c.relayAddr)
				sessionAddr = net.JoinHostPort(host, fmt.Sprintf("%d", inv.Port))
			}

			var sConn net.Conn
			if c.config.Dialer != nil {
				sConn, err = c.config.Dialer(ctx, "tcp", sessionAddr)
			} else {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				sConn, err = dialer.DialContext(ctx, "tcp", sessionAddr)
			}

			if err != nil {
				return nil, fmt.Errorf("session dial failed: %w", err)
			}
			network.OptimizeConn(sConn)

			if err := protocol.WriteMessage(sConn, protocol.MsgJoinSessionRequest, protocol.XDRBytes(inv.Key)); err != nil {
				sConn.Close()
				return nil, fmt.Errorf("session join failed: %w", err)
			}

			sConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			mType, mBody, err := protocol.ReadMessage(sConn)
			sConn.SetReadDeadline(time.Time{})

			if err != nil {
				sConn.Close()
				return nil, fmt.Errorf("session response failed: %w", err)
			}

			if mType != protocol.MsgResponse {
				sConn.Close()
				return nil, fmt.Errorf("unexpected response: %d", mType)
			}

			if len(mBody) >= 4 {
				if code := int32(binary.BigEndian.Uint32(mBody[:4])); code != 0 {
					sConn.Close()
					return nil, fmt.Errorf("session rejected: code %d", code)
				}
			}

			return sConn, nil
		}

		relayConn.Close()
		return nil, fmt.Errorf("unexpected message: %d", msgType)
	}
}

func (c *Client) completeBEPHandshake(tunnelConn net.Conn) (*yamux.Session, *tls.Conn, error) {
	bepConfig := &tls.Config{
		Certificates:       []tls.Certificate{c.config.Identity.Certificate},
		NextProtos:         []string{"bep/1.0"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificate")
			}
			remoteBytes := security.GetDeviceIDBytes(rawCerts[0])
			if len(remoteBytes) != len(c.targetBytes) {
				return errors.New("ID length mismatch")
			}
			for i := range remoteBytes {
				if remoteBytes[i] != c.targetBytes[i] {
					return errors.New("device ID mismatch")
				}
			}
			return nil
		},
	}

	bepConn := tls.Client(tunnelConn, bepConfig)

	bepConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := bepConn.Handshake(); err != nil {
		return nil, nil, fmt.Errorf("BEP handshake failed: %w", err)
	}
	bepConn.SetDeadline(time.Time{})

	session, err := yamux.Client(bepConn, defaultYamuxConfig())
	if err != nil {
		bepConn.Close()
		return nil, nil, fmt.Errorf("yamux setup failed: %w", err)
	}

	return session, bepConn, nil
}

func (c *Client) connectToRelay(ctx context.Context) (*tls.Conn, error) {
	var conn net.Conn
	var err error

	if c.config.Dialer != nil {
		conn, err = c.config.Dialer(ctx, "tcp", c.relayAddr)
	} else {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err = dialer.DialContext(ctx, "tcp", c.relayAddr)
	}

	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	network.OptimizeConn(conn)

	tlsConn := tls.Client(conn, c.tlsConfig)

	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS failed: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		tlsConn.Close()
		return nil, errors.New("no peer certificates")
	}

	if c.relayID != "" {
		relayDeviceID := security.NormalizeID(security.GetDeviceID(peerCerts[0].Raw))
		if relayDeviceID != c.relayID {
			tlsConn.Close()
			return nil, fmt.Errorf("relay ID mismatch: expected %s, got %s", c.relayID, relayDeviceID)
		}
	}

	joinPayload := make([]byte, 4)
	if err := protocol.WriteMessage(tlsConn, protocol.MsgJoinRelayRequest, joinPayload); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("join failed: %w", err)
	}

	msgType, body, err := protocol.ReadMessage(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("join response failed: %w", err)
	}

	if msgType != protocol.MsgResponse {
		tlsConn.Close()
		return nil, errors.New("join rejected")
	}

	if len(body) >= 4 {
		if code := int32(binary.BigEndian.Uint32(body[:4])); code != 0 {
			tlsConn.Close()
			return nil, fmt.Errorf("join rejected: code %d", code)
		}
	}

	return tlsConn, nil
}

func (c *Client) invalidateSessionIfMatch(gen uint64) {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	if c.sessionGen != gen {
		return // Session already replaced
	}

	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	if c.bepConn != nil {
		c.bepConn.Close()
		c.bepConn = nil
	}

	c.log("info", "Session invalidated, will reconnect on next request")
	if c.config.OnTunnelLost != nil {
		c.config.OnTunnelLost(errors.New("session invalidated"))
	}
}

func (c *Client) log(level, message string) {
	if c.config.Logger != nil {
		c.config.Logger(level, message)
	}
}