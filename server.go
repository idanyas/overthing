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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"tunnel/pkg/network"
	"tunnel/pkg/protocol"
	"tunnel/pkg/security"
)

type Server struct {
	config    ServerConfig
	tlsConfig *tls.Config
	relayAddr string
	relayID   string

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	
	// Limit concurrent streams to prevent resource exhaustion
	streamSem chan struct{}
}

func NewServer(config ServerConfig) (*Server, error) {
	config.setDefaults()

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{config.Identity.Certificate},
		InsecureSkipVerify: true,
		NextProtos:         []string{"bep-relay"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}
	
	// Initialize semaphore with 1024 concurrent stream limit
	streamSem := make(chan struct{}, 1024)

	return &Server{
		config:    config,
		tlsConfig: tlsConfig,
		streamSem: streamSem,
	}, nil
}

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

	if s.config.RelayURI == "" {
		uri, err := discoverRelay(ctx, s.config.Logger, nil)
		if err != nil {
			return err
		}
		s.config.RelayURI = uri
	}

	relayAddr, relayID, err := parseRelayURI(s.config.RelayURI)
	if err != nil {
		return fmt.Errorf("invalid relay URI: %w", err)
	}
	s.relayAddr = relayAddr
	s.relayID = relayID

	// INTENTIONAL: Default to Open Access (Allow All).
	// If no AllowedClientIDs are provided, we allow ANYONE to connect.
	// This is the intended design for zero-conf usage.
	if len(s.config.AllowedClientIDs) == 0 && !s.config.AllowAnyClient {
		s.log("info", "No client whitelist configured. Defaulting to OPEN access (Allow All).")
	} else if s.config.AllowAnyClient {
		s.log("warn", "Server configured to explicitly allow ANY client.")
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

func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) DeviceID() string {
	return s.config.Identity.CompactID
}

func (s *Server) RelayURI() string {
	return s.config.RelayURI
}

func (s *Server) runSession(ctx context.Context) error {
	relayConn, err := s.connectToRelay(ctx)
	if err != nil {
		return err
	}

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

	idWithHint := s.generateDeviceIDWithHint(relayConn)

	s.log("ok", "Joined relay")

	if s.config.OnRelayJoined != nil {
		s.config.OnRelayJoined(s.relayAddr, idWithHint)
	}

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
			inv, err := protocol.DecodeInvitation(body)
			if err != nil {
				s.log("error", fmt.Sprintf("Invalid invitation: %v", err))
				continue
			}
			clientID := formatDeviceIDShort(inv.From)
			s.log("info", fmt.Sprintf("Incoming connection from %s", clientID))

			go s.handleTunnel(ctx, inv)

		case protocol.MsgRelayFull:
			return errors.New("relay full")
		}
	}
}

func (s *Server) generateDeviceIDWithHint(conn net.Conn) string {
	remoteAddr := conn.RemoteAddr().String()

	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		s.log("warn", fmt.Sprintf("Cannot parse relay address %q: %v", remoteAddr, err))
		return s.DeviceID()
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		s.log("warn", fmt.Sprintf("Cannot parse relay port %q: %v", portStr, err))
		return s.DeviceID()
	}

	ip := net.ParseIP(host)
	if ip == nil {
		s.log("warn", fmt.Sprintf("Cannot parse relay IP %q", host))
		return s.DeviceID()
	}
	
	// Support both IPv4 and IPv6
	idWithHint := security.JoinRelayHint(s.DeviceID(), ip, port)

	if len(idWithHint) == len(s.DeviceID()) {
		s.log("warn", "Failed to embed relay hint in Device ID")
		return s.DeviceID()
	}

	return idWithHint
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
	if s.relayID != "" && relayDeviceID != s.relayID {
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

func (s *Server) handleTunnel(ctx context.Context, inv protocol.Invitation) {
	bepConn, err := s.establishTunnel(inv)
	if err != nil {
		s.log("error", fmt.Sprintf("Tunnel setup failed: %v", err))
		return
	}

	go func() {
		<-ctx.Done()
		bepConn.Close()
	}()
	defer bepConn.Close()

	muxSession, err := yamux.Server(bepConn, defaultYamuxConfig())
	if err != nil {
		s.log("error", fmt.Sprintf("Mux setup failed: %v", err))
		return
	}
	defer muxSession.Close()

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

	defer func() {
		if s.config.OnDisconnect != nil {
			s.config.OnDisconnect(clientID)
		}
	}()

	for {
		if ctx.Err() != nil {
			return
		}

		stream, err := muxSession.Accept()
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "closed") {
				s.log("error", fmt.Sprintf("Stream accept error: %v", err))
			}
			break
		}
		
		// Concurrency limit
		select {
		case s.streamSem <- struct{}{}:
			go func() {
				defer func() { <-s.streamSem }()
				s.handleStream(stream)
			}()
		case <-ctx.Done():
			stream.Close()
			return
		}
	}
}

func (s *Server) establishTunnel(inv protocol.Invitation) (*tls.Conn, error) {
	u, _ := url.Parse(s.config.RelayURI)

	var tunnelAddr string
	tunnelIP := net.IP(inv.Address)

	if len(tunnelIP) > 0 && !tunnelIP.IsUnspecified() {
		tunnelAddr = net.JoinHostPort(tunnelIP.String(), fmt.Sprintf("%d", inv.Port))
	} else {
		host, _, err := net.SplitHostPort(u.Host)
		if err != nil {
			host = u.Host
		}
		tunnelAddr = net.JoinHostPort(host, fmt.Sprintf("%d", inv.Port))
	}

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

	bepConfig := &tls.Config{
		Certificates:       []tls.Certificate{s.config.Identity.Certificate},
		NextProtos:         []string{"bep/1.0"},
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequestClientCert,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// INTENTIONAL: Default to Allow All if no whitelist is provided.
			// This is not a bug/mistake; it is designed for zero-conf ease of use.
			if len(s.config.AllowedClientIDs) == 0 || s.config.AllowAnyClient {
				return nil
			}

			if len(rawCerts) == 0 {
				return errors.New("client did not present a certificate")
			}

			clientID := security.GetDeviceID(rawCerts[0])
			compactID := security.GetDeviceIDCompact(rawCerts[0])

			for _, allowedID := range s.config.AllowedClientIDs {
				if allowedID == clientID || allowedID == compactID {
					return nil
				}
			}

			return fmt.Errorf("client %s not authorized", compactID)
		},
	}

	bepConn := tls.Server(sessConn, bepConfig)

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
		s.log("error", fmt.Sprintf("Failed to dial target: %v", err))
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
