package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/idanyas/overthing/pkg/network"
	"github.com/idanyas/overthing/pkg/protocol"
	"github.com/idanyas/overthing/pkg/relay"
	"github.com/idanyas/overthing/pkg/security"
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

	// Automatic Connectivity Test
	go func() {
		c.log("info", "Verifying connectivity to server...")

		testCtx, testCancel := context.WithTimeout(ctx, 30*time.Second)
		defer testCancel()

		// Force a session establishment
		if _, err := c.getSession(testCtx); err != nil {
			c.log("warn", fmt.Sprintf("Initial connection test failed: %v", err))
			c.log("info", "Client will keep retrying when connections arrive...")
		} else {
			c.log("ok", "Connectivity verified. Tunnel is ready.")
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

	// Attempt to open a stream. If the session is dead, we retry once.
	var stream net.Conn
	var err error
	var session *yamux.Session
	var sessionGen uint64

	for retry := 0; retry < 2; retry++ {
		session, sessionGen, err = c.getSessionWithGen(ctx)
		if err != nil {
			c.log("error", fmt.Sprintf("Session failed: %v", err))
			return
		}

		stream, err = session.Open()
		if err == nil {
			break // Success
		}

		c.log("warn", fmt.Sprintf("Stream open failed (attempt %d): %v - invalidating session", retry+1, err))
		c.invalidateSessionIfMatch(sessionGen)
	}

	if err != nil {
		c.log("error", fmt.Sprintf("Failed to open stream after retry: %v", err))
		return
	}
	defer stream.Close()

	network.CopyBidirectional(stream, localConn)
}

func (c *Client) getSession(ctx context.Context) (*yamux.Session, error) {
	session, _, err := c.getSessionWithGen(ctx)
	return session, err
}

func (c *Client) getSessionWithGen(ctx context.Context) (*yamux.Session, uint64, error) {
	// Fast path: check if we have a valid session without full lock
	c.muxMu.RLock()
	session := c.session
	gen := c.sessionGen

	if session != nil && !session.IsClosed() {
		c.muxMu.RUnlock()
		return session, gen, nil
	}
	c.muxMu.RUnlock()

	// Slow path: need to create new session
	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	// Double-check after acquiring write lock
	if c.session != nil && !c.session.IsClosed() {
		return c.session, c.sessionGen, nil
	}

	// Clean up old session
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	if c.bepConn != nil {
		c.bepConn.Close()
		c.bepConn = nil
	}

	// Try to establish session
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
	var tunnelConn net.Conn
	var err error

	// If no relay configured, scan to find one
	if c.config.RelayURI == "" {
		if c.isFixedRelay {
			return nil, nil, errors.New("relay URI missing in fixed configuration")
		}

		c.log("info", "Scanning network for target device...")
		tunnelConn, relayURI, err := c.scanAndConnect(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("discovery failed: %w", err)
		}

		// Save the discovered relay for future reconnections
		c.config.RelayURI = relayURI
		c.relayAddr, c.relayID, _ = parseRelayURI(relayURI)

		// Complete BEP handshake
		session, bepConn, err := c.completeBEPHandshake(tunnelConn)
		if err != nil {
			tunnelConn.Close()
			return nil, nil, err
		}

		return session, bepConn, nil
	}

	// Connect to known relay with retries
	for attempt := 0; attempt < 3; attempt++ {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}

		tunnelConn, err = c.connectToKnownRelay(ctx)
		if err != nil {
			c.log("warn", fmt.Sprintf("Connection attempt %d failed: %v", attempt+1, err))

			if attempt < 2 {
				time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
				continue
			}

			// If not a fixed relay, try rescanning
			if !c.isFixedRelay {
				c.log("info", "Clearing cached relay to re-scan...")
				c.config.RelayURI = ""
				c.relayAddr = ""
				c.relayID = ""
				return c.establishNewSession(ctx) // Recursive call to scan
			}
			return nil, nil, err
		}

		session, bepConn, err := c.completeBEPHandshake(tunnelConn)
		if err != nil {
			tunnelConn.Close()
			c.log("warn", fmt.Sprintf("Handshake attempt %d failed: %v", attempt+1, err))

			if attempt < 2 {
				time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
				continue
			}
			return nil, nil, err
		}

		return session, bepConn, nil
	}

	return nil, nil, errors.New("failed to establish session after retries")
}

// scanAndConnect finds the target device and returns a ready tunnel connection
func (c *Client) scanAndConnect(ctx context.Context) (net.Conn, string, error) {
	c.log("info", "Fetching public relay list...")
	relays, err := relay.Discover(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("fetch relays: %w", err)
	}

	c.log("info", fmt.Sprintf("Scanning %d relays for device %x...", len(relays), c.targetBytes[:4]))

	type result struct {
		conn     net.Conn
		relayURI string
	}

	results := make(chan result, 1)
	scanCtx, scanCancel := context.WithCancel(ctx)
	defer scanCancel()

	var found int32

	// Reduce worker count to avoid network saturation and FD limits.
	// 300 was too high causing connection timeouts.
	workers := 100
	if len(relays) < workers {
		workers = len(relays)
	}

	work := make(chan relay.Relay, len(relays))
	for _, r := range relays {
		work <- r
	}
	close(work)

	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for r := range work {
				if atomic.LoadInt32(&found) != 0 {
					return
				}

				select {
				case <-scanCtx.Done():
					return
				default:
				}

				conn, err := c.tryRelayAndConnect(scanCtx, r)
				if err != nil {
					continue
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
				return
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	select {
	case res, ok := <-results:
		if !ok {
			return nil, "", errors.New("target device not found on any relay")
		}

		u, _ := url.Parse(res.relayURI)
		c.log("ok", fmt.Sprintf("Found device on relay: %s", u.Host))

		return res.conn, res.relayURI, nil
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

// tryRelayAndConnect connects to a relay, requests connection to target, and returns the tunnel
func (c *Client) tryRelayAndConnect(ctx context.Context, r relay.Relay) (net.Conn, error) {
	// Increased timeout to 15s to allow for full relay session establishment.
	// Previous 5s was too short for the Server to receive invitation and dial back.
	probeCtx, probeCancel := context.WithTimeout(ctx, 15*time.Second)
	defer probeCancel()

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	addr := net.JoinHostPort(r.Host, r.Port)
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(probeCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if deadline, ok := probeCtx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	network.OptimizeConn(conn)

	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.ServerName = host

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	// Join relay
	if err := protocol.WriteMessage(tlsConn, protocol.MsgJoinRelayRequest, []byte{0, 0, 0, 0}); err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Read Join Response
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
			if len(body) >= 4 && int32(binary.BigEndian.Uint32(body[:4])) != 0 {
				tlsConn.Close()
				return nil, errors.New("join rejected")
			}
			break
		}
		tlsConn.Close()
		return nil, errors.New("unexpected message")
	}

	// Send Connect Request
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
			tlsConn.Close()
			return nil, errors.New("target not found")
		}

		if msgType == protocol.MsgSessionInvitation {
			inv, err := protocol.DecodeInvitation(body)
			if err != nil {
				tlsConn.Close()
				return nil, err
			}

			// Verify invitation is from our target
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

			// Close relay connection - we're done with it
			tlsConn.Close()

			// Connect to session
			var sessionAddr string
			if len(inv.Address) > 0 && !net.IP(inv.Address).IsUnspecified() {
				sessionAddr = net.JoinHostPort(net.IP(inv.Address).String(), fmt.Sprintf("%d", inv.Port))
			} else {
				sessionAddr = net.JoinHostPort(host, fmt.Sprintf("%d", inv.Port))
			}

			sConn, err := net.DialTimeout("tcp", sessionAddr, 5*time.Second)
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

// connectToKnownRelay connects to a known relay and returns the tunnel connection
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
		relayConn.SetReadDeadline(time.Now().Add(30 * time.Second))
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
			relayConn.Close()
			if len(body) >= 4 {
				code := int32(binary.BigEndian.Uint32(body[:4]))
				if code != 0 {
					return nil, fmt.Errorf("connect rejected: code %d", code)
				}
			}
			return nil, errors.New("unexpected response")
		}

		if msgType == protocol.MsgSessionInvitation {
			inv, err := protocol.DecodeInvitation(body)
			if err != nil {
				relayConn.Close()
				return nil, err
			}

			// Verify invitation
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

			sConn, err := net.DialTimeout("tcp", sessionAddr, 10*time.Second)
			if err != nil {
				return nil, fmt.Errorf("session dial failed: %w", err)
			}
			network.OptimizeConn(sConn)

			if err := protocol.WriteMessage(sConn, protocol.MsgJoinSessionRequest, protocol.XDRBytes(inv.Key)); err != nil {
				sConn.Close()
				return nil, fmt.Errorf("session join failed: %w", err)
			}

			sConn.SetReadDeadline(time.Now().Add(10 * time.Second))
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
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.relayAddr)
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
