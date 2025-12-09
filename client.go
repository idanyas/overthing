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
	"time"

	"github.com/hashicorp/yamux"

	"tunnel/pkg/network"
	"tunnel/pkg/protocol"
	"tunnel/pkg/security"
)

// Client represents a tunnel client that connects to a tunnel server
// through a Syncthing relay and exposes it as a local TCP listener.
type Client struct {
	config      ClientConfig
	tlsConfig   *tls.Config
	targetBytes []byte
	relayAddr   string
	relayID     string

	mu       sync.Mutex
	running  bool
	cancel   context.CancelFunc
	listener net.Listener

	muxMu     sync.Mutex
	session   *yamux.Session
	bepConn   *tls.Conn
	lastError time.Time
}

// NewClient creates a new tunnel client with the given configuration.
// If RelayURI is not specified, automatically discovers the fastest relay.
func NewClient(config ClientConfig) (*Client, error) {
	config.setDefaults()

	targetBytes, err := security.DeviceIDFromString(config.TargetID)
	if err != nil {
		return nil, fmt.Errorf("invalid target device ID: %w", err)
	}

	// Auto-discover relay if not specified
	if config.RelayURI == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		
		uri, err := discoverRelay(ctx, config.Logger)
		if err != nil {
			return nil, err
		}
		config.RelayURI = uri
	}

	relayAddr, relayID, err := parseRelayURI(config.RelayURI)
	if err != nil {
		return nil, fmt.Errorf("invalid relay URI: %w", err)
	}

	// TLS Config for the Relay connection (checking Relay ID)
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{config.Identity.Certificate},
		InsecureSkipVerify: true,
		NextProtos:         []string{"bep-relay"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	return &Client{
		config:      config,
		tlsConfig:   tlsConfig,
		targetBytes: targetBytes,
		relayAddr:   relayAddr,
		relayID:     relayID,
	}, nil
}

// Run starts the client and blocks until the context is cancelled.
// It listens on the configured address and forwards connections through the tunnel.
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
		c.log("ok", fmt.Sprintf("Listening on custom listener: %s", listener.Addr()))
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

	for {
		localConn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Avoid hot-loop on temporary errors
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		network.OptimizeConn(localConn)
		go c.handleConnection(ctx, localConn)
	}
}

// Stop gracefully stops the client.
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

// DeviceID returns the client's device ID in compact format.
func (c *Client) DeviceID() string {
	return c.config.Identity.CompactID
}

// ListenAddr returns the address the client is listening on.
func (c *Client) ListenAddr() string {
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return c.config.ListenAddr
}

// RelayURI returns the relay URI being used.
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

	// Cleanup old session
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
	if c.bepConn != nil {
		c.bepConn.Close()
		c.bepConn = nil
	}

	// Rate limit reconnection attempts
	if time.Since(c.lastError) < 100*time.Millisecond {
		time.Sleep(100 * time.Millisecond)
	}

	relayConn, err := c.connectToRelay(ctx)
	if err != nil {
		c.lastError = time.Now()
		return nil, err
	}

	if err := protocol.WriteMessage(relayConn, protocol.MsgConnectRequest, protocol.XDRBytes(c.targetBytes)); err != nil {
		relayConn.Close()
		c.lastError = time.Now()
		return nil, err
	}

	relayConn.SetReadDeadline(time.Now().Add(60 * time.Second))

	var inv protocol.Invitation
	for {
		msgType, body, err := protocol.ReadMessage(relayConn)
		if err != nil {
			relayConn.Close()
			c.lastError = time.Now()
			return nil, err
		}

		switch msgType {
		case protocol.MsgPing:
			protocol.WriteMessage(relayConn, protocol.MsgPong, nil)
		case protocol.MsgResponse:
			if len(body) >= 4 && int32(binary.BigEndian.Uint32(body[:4])) != 0 {
				relayConn.Close()
				c.lastError = time.Now()
				return nil, errors.New("connection rejected")
			}
		case protocol.MsgSessionInvitation:
			inv = protocol.DecodeInvitation(body)
			goto connected
		}
	}

connected:
	relayConn.Close()

	bepConn, err := c.establishTunnel(inv)
	if err != nil {
		c.lastError = time.Now()
		if c.config.OnTunnelLost != nil {
			c.config.OnTunnelLost(err)
		}
		return nil, err
	}

	session, err := yamux.Client(bepConn, defaultYamuxConfig())
	if err != nil {
		bepConn.Close()
		c.lastError = time.Now()
		return nil, err
	}

	c.session = session
	c.bepConn = bepConn

	c.log("ok", "Tunnel established (multiplexed)")
	if c.config.OnTunnelEstablished != nil {
		c.config.OnTunnelEstablished()
	}

	return session, nil
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
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		tlsConn.Close()
		return nil, errors.New("no peer certificates")
	}

	relayDeviceID := security.NormalizeID(security.GetDeviceID(peerCerts[0].Raw))
	if relayDeviceID != c.relayID {
		tlsConn.Close()
		return nil, errors.New("relay ID mismatch")
	}

	joinPayload := make([]byte, 4)
	if err := protocol.WriteMessage(tlsConn, protocol.MsgJoinRelayRequest, joinPayload); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("join request failed: %w", err)
	}

	msgType, body, err := protocol.ReadMessage(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("join response failed: %w", err)
	}

	if msgType != protocol.MsgResponse {
		tlsConn.Close()
		return nil, errors.New("join rejected: wrong message type")
	}

	if len(body) >= 4 {
		if code := int32(binary.BigEndian.Uint32(body[:4])); code != 0 {
			tlsConn.Close()
			return nil, fmt.Errorf("join rejected: code %d", code)
		}
	}

	return tlsConn, nil
}

func (c *Client) establishTunnel(inv protocol.Invitation) (*tls.Conn, error) {
	u, _ := url.Parse(c.config.RelayURI)

	tunnelIP := net.IP(inv.Address)
	if len(tunnelIP) == 0 || tunnelIP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(u.Host)
		tunnelIP = net.ParseIP(host)
	}

	if tunnelIP == nil {
		return nil, errors.New("cannot determine tunnel IP")
	}

	tunnelAddr := net.JoinHostPort(tunnelIP.String(), fmt.Sprintf("%d", inv.Port))

	sessConn, err := net.DialTimeout("tcp", tunnelAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("session dial failed: %w", err)
	}

	network.OptimizeConn(sessConn)

	if err := protocol.WriteMessage(sessConn, protocol.MsgJoinSessionRequest, protocol.XDRBytes(inv.Key)); err != nil {
		sessConn.Close()
		return nil, fmt.Errorf("session join failed: %w", err)
	}

	sessConn.SetReadDeadline(time.Now().Add(15 * time.Second))
	msgType, body, err := protocol.ReadMessage(sessConn)
	sessConn.SetReadDeadline(time.Time{})

	if err != nil {
		sessConn.Close()
		return nil, fmt.Errorf("session response failed: %w", err)
	}

	if msgType != protocol.MsgResponse {
		sessConn.Close()
		return nil, errors.New("session rejected: wrong message type")
	}

	if len(body) >= 4 {
		if code := int32(binary.BigEndian.Uint32(body[:4])); code != 0 {
			sessConn.Close()
			return nil, fmt.Errorf("session rejected: code %d", code)
		}
	}

	// SECURITY FIX: Verify the Server's identity matches expected TargetID
	bepConfig := &tls.Config{
		Certificates:       []tls.Certificate{c.config.Identity.Certificate},
		NextProtos:         []string{"bep/1.0"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // We verify certificate manually
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no peer certificates presented")
			}
			remoteBytes := security.GetDeviceIDBytes(rawCerts[0])
			if len(remoteBytes) != len(c.targetBytes) {
				return errors.New("device ID length mismatch")
			}
			for i := range remoteBytes {
				if remoteBytes[i] != c.targetBytes[i] {
					return fmt.Errorf("device ID mismatch: expected %x, got %x", c.targetBytes, remoteBytes)
				}
			}
			return nil
		},
	}

	var bepConn *tls.Conn
	if inv.ServerSocket {
		serverConfig := bepConfig.Clone()
		serverConfig.ClientAuth = tls.RequestClientCert
		bepConn = tls.Server(sessConn, serverConfig)
	} else {
		bepConn = tls.Client(sessConn, bepConfig)
	}

	bepConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := bepConn.Handshake(); err != nil {
		sessConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	bepConn.SetDeadline(time.Time{})

	return bepConn, nil
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
