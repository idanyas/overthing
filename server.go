package tunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"tunnel/pkg/network"
	"tunnel/pkg/protocol"
	"tunnel/pkg/security"
)

// Server represents a tunnel server that accepts incoming connections
// through a Syncthing relay and forwards them to a local address.
type Server struct {
	config    ServerConfig
	tlsConfig *tls.Config
	relayAddr string
	relayID   string

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
}

// NewServer creates a new tunnel server with the given configuration.
// If RelayURI is not specified, automatically discovers the fastest relay.
func NewServer(config ServerConfig) (*Server, error) {
	config.setDefaults()

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

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{config.Identity.Certificate},
		InsecureSkipVerify: true,
		NextProtos:         []string{"bep-relay"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	return &Server{
		config:    config,
		tlsConfig: tlsConfig,
		relayAddr: relayAddr,
		relayID:   relayID,
	}, nil
}

// Run starts the server and blocks until the context is cancelled.
// It automatically reconnects to the relay on connection loss.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("server already running")
	}
	s.running = true
	ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	// Log security status
	if len(s.config.AllowedClientIDs) == 0 && !s.config.AllowAnyClient {
		s.log("warn", "No allowed clients configured. Server is open to ALL connections.")
	} else if s.config.AllowAnyClient {
		s.log("warn", "Server configured to allow ANY client.")
	} else {
		s.log("info", fmt.Sprintf("Access restricted to %d client(s)", len(s.config.AllowedClientIDs)))
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := s.runSession(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err != nil {
			s.log("error", fmt.Sprintf("Session error: %v", err))
			time.Sleep(s.config.ReconnectDelay)
		}
	}
}

// Stop gracefully stops the server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

// DeviceID returns the server's device ID in compact format.
func (s *Server) DeviceID() string {
	return s.config.Identity.CompactID
}

// FullDeviceID returns the server's device ID in full Syncthing format.
func (s *Server) FullDeviceID() string {
	return s.config.Identity.FullID
}

// RelayURI returns the relay URI being used.
func (s *Server) RelayURI() string {
	return s.config.RelayURI
}

func (s *Server) runSession(ctx context.Context) error {
	relayConn, err := s.connectToRelay(ctx)
	if err != nil {
		return err
	}

	// Create a monitoring goroutine to close the connection immediately
	// upon context cancellation. This ensures ReadMessage unblocks.
	done := make(chan struct{})
	defer close(done)
	
	go func() {
		select {
		case <-ctx.Done():
			relayConn.Close()
		case <-done:
		}
	}()

	defer relayConn.Close()

	s.log("info", "Waiting for connections...")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		relayConn.SetReadDeadline(time.Now().Add(90 * time.Second))
		msgType, body, err := protocol.ReadMessage(relayConn)
		if err != nil {
			return fmt.Errorf("relay read: %w", err)
		}

		switch msgType {
		case protocol.MsgPing:
			protocol.WriteMessage(relayConn, protocol.MsgPong, nil)

		case protocol.MsgSessionInvitation:
			inv := protocol.DecodeInvitation(body)
			clientID := formatDeviceIDShort(inv.From)
			s.log("info", fmt.Sprintf("Incoming connection attempt from %s", clientID))
			go s.handleTunnel(inv)

		case protocol.MsgRelayFull:
			return errors.New("relay full")
		}
	}
}

func (s *Server) connectToRelay(ctx context.Context) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", s.relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial failed: %w", err)
	}

	network.OptimizeConn(conn)

	tlsConn := tls.Client(conn, s.tlsConfig)

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
	if relayDeviceID != s.relayID {
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

	s.log("ok", "Joined relay")
	return tlsConn, nil
}

func (s *Server) handleTunnel(inv protocol.Invitation) {
	bepConn, err := s.establishTunnel(inv)
	if err != nil {
		s.log("error", fmt.Sprintf("Tunnel setup failed: %v", err))
		return
	}
	defer bepConn.Close()

	muxSession, err := yamux.Server(bepConn, defaultYamuxConfig())
	if err != nil {
		s.log("error", fmt.Sprintf("Mux setup failed: %v", err))
		return
	}
	defer muxSession.Close()

	// Re-verify client identity from the established connection
	peerCerts := bepConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		s.log("error", "No peer certs in established tunnel")
		return
	}
	clientID := formatDeviceIDShort(security.GetDeviceIDBytes(peerCerts[0].Raw))
	
	s.log("ok", fmt.Sprintf("Tunnel ready from %s (multiplexed)", clientID))

	if s.config.OnConnect != nil {
		s.config.OnConnect(clientID)
	}

	for {
		stream, err := muxSession.Accept()
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				s.log("error", fmt.Sprintf("Stream accept error: %v", err))
			}
			break
		}
		go s.handleStream(stream)
	}

	if s.config.OnDisconnect != nil {
		s.config.OnDisconnect(clientID)
	}
}

func (s *Server) establishTunnel(inv protocol.Invitation) (*tls.Conn, error) {
	u, _ := url.Parse(s.config.RelayURI)

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

	// SECURITY: Verify Client
	bepConfig := &tls.Config{
		Certificates:       []tls.Certificate{s.config.Identity.Certificate},
		NextProtos:         []string{"bep/1.0"},
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: true, // Manual verification
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if s.config.AllowAnyClient {
				return nil
			}
			
			// Backward compatibility: If no allowed clients are specified, default to OPEN.
			if len(s.config.AllowedClientIDs) == 0 {
				return nil
			}

			if len(rawCerts) == 0 {
				return errors.New("client did not present a certificate")
			}
			
			// Calculate ID
			clientID := security.GetDeviceID(rawCerts[0])
			compactID := security.GetDeviceIDCompact(rawCerts[0])
			
			allowed := false
			for _, allowedID := range s.config.AllowedClientIDs {
				if allowedID == clientID || allowedID == compactID {
					allowed = true
					break
				}
			}
			
			if !allowed {
				return fmt.Errorf("client %s not authorized", compactID)
			}
			return nil
		},
	}

	var bepConn *tls.Conn
	if inv.ServerSocket {
		bepConn = tls.Server(sessConn, bepConfig)
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

func (s *Server) handleStream(stream net.Conn) {
	defer stream.Close()

	var targetConn net.Conn
	var err error

	if s.config.TargetDialer != nil {
		targetConn, err = s.config.TargetDialer()
	} else {
		targetConn, err = net.DialTimeout("tcp", s.config.ForwardAddr, 10*time.Second)
	}

	if err != nil {
		return
	}
	defer targetConn.Close()

	network.OptimizeConn(targetConn)
	network.CopyBidirectional(stream, targetConn)
}

func (s *Server) log(level, message string) {
	if s.config.Logger != nil {
		s.config.Logger(level, message)
	}
}
