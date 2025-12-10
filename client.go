package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"tunnel/pkg/network"
	"tunnel/pkg/protocol"
	"tunnel/pkg/relay"
	"tunnel/pkg/security"
)

type Client struct {
	config      ClientConfig
	tlsConfig   *tls.Config
	targetBytes []byte
	
	// State for relay connection
	relayAddr    string
	relayID      string
	isFixedRelay bool // true if provided by user config, false if dynamic (hint/discovery)

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	listener net.Listener

	muxMu     sync.Mutex
	session   *yamux.Session
	bepConn   *tls.Conn
	lastError time.Time
}

func NewClient(config ClientConfig) (*Client, error) {
	config.setDefaults()

	// Check for Relay Hint in the Device ID
	cleanID, hintIP, hintPort, hasHint := security.SplitRelayHint(config.TargetID)
	config.TargetID = cleanID
	
	targetBytes, err := security.DeviceIDFromString(config.TargetID)
	if err != nil {
		return nil, fmt.Errorf("invalid target device ID: %w", err)
	}

	isFixedRelay := false

	// Connection Strategy:
	// 1. Explicit RelayURI in config -> Fixed. Never scan.
	// 2. Hint in Device ID -> Dynamic. Try hint first, then scan if fails.
	// 3. Neither -> Dynamic. Scan immediately.

	if config.RelayURI != "" {
		isFixedRelay = true
		if config.Logger != nil {
			config.Logger("info", fmt.Sprintf("Using configured relay: %s", config.RelayURI))
		}
	} else if hasHint {
		// Populate RelayURI from hint, but keep isFixedRelay = false
		config.RelayURI = fmt.Sprintf("relay://%s:%d", hintIP.String(), hintPort)
		if config.Logger != nil {
			config.Logger("ok", fmt.Sprintf("Extracted relay hint: %s:%d", hintIP, hintPort))
		}
	} else {
		// No URI, no hint. Will trigger scan in getSession.
		if config.Logger != nil {
			config.Logger("info", "No relay hint. Will scan network for target.")
		}
	}

	// Parse the URI if we have one now
	var relayAddr, relayID string
	if config.RelayURI != "" {
		// Reusing 'err' from above, no 'var err error' here
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

func (c *Client) DeviceID() string {
	return c.config.Identity.CompactID
}

func (c *Client) ListenAddr() string {
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return c.config.ListenAddr
}

func (c *Client) RelayURI() string {
	return c.config.RelayURI
}

func (c *Client) handleConnection(ctx context.Context, localConn net.Conn) {
	defer localConn.Close()

	session, err := c.getSession(ctx)
	if err != nil {
		c.log("error", fmt.Sprintf("Session failed: %v", err))
		return
	}

	stream, err := session.Open()
	if err != nil {
		c.invalidateSession(session)
		c.log("error", fmt.Sprintf("Stream failed: %v", err))
		return
	}
	defer stream.Close()

	network.CopyBidirectional(stream, localConn)
}

func (c *Client) getSession(ctx context.Context) (*yamux.Session, error) {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	if c.session != nil && !c.session.IsClosed() {
		return c.session, nil
	}

	// Clean up old session if existing
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	if c.bepConn != nil {
		c.bepConn.Close()
		c.bepConn = nil
	}

	// Rate limit retries slightly
	if time.Since(c.lastError) < 100*time.Millisecond {
		time.Sleep(100 * time.Millisecond)
	}

	for {
		// 1. Resolve Relay URI
		// If we don't have a URI (or we cleared it due to error), and we aren't fixed, find one.
		if c.config.RelayURI == "" {
			if c.isFixedRelay {
				return nil, errors.New("relay URI missing in fixed configuration")
			}
			
			c.log("info", "Scanning network for target device...")
			uri, err := c.scanRelays(ctx)
			if err != nil {
				c.lastError = time.Now()
				// If scanning fails, wait a bit before retrying the loop
				time.Sleep(2 * time.Second)
				return nil, fmt.Errorf("discovery failed: %w", err)
			}
			
			c.config.RelayURI = uri
			c.relayAddr, c.relayID, err = parseRelayURI(uri)
			if err != nil {
				c.config.RelayURI = "" // Bad URI, try again
				return nil, fmt.Errorf("resolved invalid URI: %w", err)
			}
		}

		// 2. Connect to Relay
		relayConn, err := c.connectToRelay(ctx)
		if err != nil {
			c.log("warn", fmt.Sprintf("Relay connection failed: %v", err))
			
			// If not fixed, clear URI to trigger scan next loop
			if !c.isFixedRelay {
				c.log("info", "Relay unreachable. Clearing cached relay to re-scan...")
				c.config.RelayURI = ""
				continue
			}
			c.lastError = time.Now()
			return nil, err
		}

		// 3. Connect to Target via Relay
		if err := protocol.WriteMessage(relayConn, protocol.MsgConnectRequest, protocol.XDRBytes(c.targetBytes)); err != nil {
			relayConn.Close()
			c.lastError = time.Now()
			
			if !c.isFixedRelay {
				c.config.RelayURI = ""
				continue
			}
			return nil, err
		}

		relayConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		msgType, body, err := protocol.ReadMessage(relayConn)
		if err != nil {
			relayConn.Close()
			c.lastError = time.Now()
			if !c.isFixedRelay {
				c.config.RelayURI = ""
				continue
			}
			return nil, err
		}

		var tunnelConn net.Conn

		if msgType == protocol.MsgResponse {
			if len(body) >= 4 {
				code := int32(binary.BigEndian.Uint32(body[:4]))
				
				if code != 0 {
					relayConn.Close()
					c.lastError = time.Now()
					
					// Code 1: Not Found
					if code == 1 { 
						c.log("warn", "Target device not found on this relay")
						
						if !c.isFixedRelay {
							c.log("info", "Device likely moved. Re-scanning network...")
							c.config.RelayURI = ""
							continue
						}
					}

					return nil, fmt.Errorf("relay rejected connect request: code %d", code)
				}
			}
			tunnelConn = relayConn
			tunnelConn.SetReadDeadline(time.Time{})

		} else if msgType == protocol.MsgSessionInvitation {
			inv, err := protocol.DecodeInvitation(body)
			if err != nil {
				relayConn.Close()
				c.lastError = time.Now()
				return nil, fmt.Errorf("invalid invitation: %w", err)
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
				c.lastError = time.Now()
				if !c.isFixedRelay {
					c.config.RelayURI = "" // Session establishment failed, maybe try another relay
					continue
				}
				return nil, fmt.Errorf("session dial failed: %w", err)
			}
			network.OptimizeConn(sConn)

			if err := protocol.WriteMessage(sConn, protocol.MsgJoinSessionRequest, protocol.XDRBytes(inv.Key)); err != nil {
				sConn.Close()
				c.lastError = time.Now()
				return nil, fmt.Errorf("session join failed: %w", err)
			}

			sConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			mType, mBody, err := protocol.ReadMessage(sConn)
			sConn.SetReadDeadline(time.Time{})

			if err != nil {
				sConn.Close()
				c.lastError = time.Now()
				return nil, fmt.Errorf("session response failed: %w", err)
			}

			if mType != protocol.MsgResponse {
				sConn.Close()
				c.lastError = time.Now()
				return nil, fmt.Errorf("unexpected response: %d", mType)
			}

			if len(mBody) >= 4 {
				if code := int32(binary.BigEndian.Uint32(mBody[:4])); code != 0 {
					sConn.Close()
					c.lastError = time.Now()
					if !c.isFixedRelay {
						c.config.RelayURI = ""
						continue
					}
					return nil, fmt.Errorf("session rejected: code %d", code)
				}
			}
			tunnelConn = sConn

		} else {
			relayConn.Close()
			c.lastError = time.Now()
			return nil, fmt.Errorf("unexpected message: %d", msgType)
		}

		// 4. BEP Handshake
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
						return fmt.Errorf("device ID mismatch")
					}
				}
				return nil
			},
		}

		bepConn := tls.Client(tunnelConn, bepConfig)

		bepConn.SetDeadline(time.Now().Add(15 * time.Second))
		if err := bepConn.Handshake(); err != nil {
			tunnelConn.Close()
			c.lastError = time.Now()
			// TLS handshake failure usually implies correct relay but protocol issue
			// or severe network glitch. Not necessarily wrong relay, but safer to return error
			// than aggressively scan unless the error is specific.
			return nil, fmt.Errorf("BEP handshake failed: %w", err)
		}
		bepConn.SetDeadline(time.Time{})

		session, err := yamux.Client(bepConn, defaultYamuxConfig())
		if err != nil {
			bepConn.Close()
			c.lastError = time.Now()
			return nil, err
		}

		c.session = session
		c.bepConn = bepConn

		c.log("ok", "Tunnel established")
		if c.config.OnTunnelEstablished != nil {
			c.config.OnTunnelEstablished()
		}

		return session, nil
	}
}

// scanRelays fetches all public relays and probes them for the target device.
func (c *Client) scanRelays(ctx context.Context) (string, error) {
	c.log("info", "Fetching public relay list...")
	relays, err := relay.Discover(ctx)
	if err != nil {
		return "", fmt.Errorf("fetch relays: %w", err)
	}

	c.log("info", fmt.Sprintf("Scanning %d relays for device %x...", len(relays), c.targetBytes[:4]))

	type result struct {
		uri string
		err error
	}

	results := make(chan result, 1)
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 500 workers ensures we clear the queue rapidly.
	// With 700 relays and 2s timeout, we finish in ~3-4 seconds max.
	const workers = 500
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
				// Check for stop signal
				select {
				case <-scanCtx.Done():
					return
				default:
				}

				if c.probeRelay(scanCtx, r) {
					select {
					case results <- result{uri: r.URL}:
						cancel() // Stop all other workers immediately
					default:
					}
					return
				}
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
			return "", errors.New("target device not found on any relay")
		}
		if res.err != nil {
			return "", res.err
		}
		c.log("ok", fmt.Sprintf("Found device on relay: %s", res.uri))
		return res.uri, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// probeRelay checks a single relay for the target device
func (c *Client) probeRelay(ctx context.Context, r relay.Relay) bool {
	// 2.0s strict timeout per relay. This is enough for a good connection.
	ctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
	defer cancel()

	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	
	addr := net.JoinHostPort(r.Host, r.Port)
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// IMPORTANT: Set absolute deadline on the connection for all I/O.
	// DialContext only handles the dial. The context doesn't apply to Handshake/Read/Write automatically.
	// If the relay accepts TCP but hangs, Handshake would block forever without this.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(2000 * time.Millisecond))
	}

	tlsConfig := c.tlsConfig.Clone()
	tlsConfig.ServerName = host
	
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return false
	}

	if err := protocol.WriteMessage(tlsConn, protocol.MsgJoinRelayRequest, []byte{0, 0, 0, 0}); err != nil {
		return false
	}
	
	msgType, body, err := protocol.ReadMessage(tlsConn)
	if err != nil || msgType != protocol.MsgResponse {
		return false
	}
	if len(body) >= 4 && int32(binary.BigEndian.Uint32(body[:4])) != 0 {
		return false
	}

	if err := protocol.WriteMessage(tlsConn, protocol.MsgConnectRequest, protocol.XDRBytes(c.targetBytes)); err != nil {
		return false
	}

	msgType, body, err = protocol.ReadMessage(tlsConn)
	if err != nil {
		return false
	}

	if msgType == protocol.MsgSessionInvitation {
		return true
	}

	if msgType == protocol.MsgResponse {
		if len(body) >= 4 {
			code := int32(binary.BigEndian.Uint32(body[:4]))
			if code == 0 {
				return true
			}
		}
	}

	return false
}

func (c *Client) connectToRelay(ctx context.Context) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", c.relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	network.OptimizeConn(conn)

	tlsConn := tls.Client(conn, c.tlsConfig)

	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
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
			return nil, errors.New("relay ID mismatch")
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

func (c *Client) invalidateSession(session *yamux.Session) {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()
	if c.session == session {
		if c.session != nil {
			c.session.Close()
		}
		c.session = nil
		if c.bepConn != nil {
			c.bepConn.Close()
			c.bepConn = nil
		}
		c.lastError = time.Now()
		if c.config.OnTunnelLost != nil {
			c.config.OnTunnelLost(errors.New("session invalidated"))
		}
	}
}

func (c *Client) log(level, message string) {
	if c.config.Logger != nil {
		c.config.Logger(level, message)
	}
}
