package tunnel

import (
	"context"
	"net"
	"time"
)

// DialerFunc represents a function that can dial a network connection.
// It matches the signature of net.Dialer.DialContext.
type DialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ServerConfig contains configuration options for a tunnel server.
type ServerConfig struct {
	// Identity is the server's identity for authentication.
	// Required.
	Identity Identity

	// ForwardAddr is the local address to forward incoming connections to.
	// Default: "127.0.0.1:22"
	// Ignored if TargetDialer is set.
	ForwardAddr string

	// TargetDialer is an optional function to dial the destination service.
	// If provided, it overrides ForwardAddr.
	// This allows forwarding to non-TCP endpoints (e.g. Unix sockets, memory pipes).
	TargetDialer func() (net.Conn, error)

	// RelayURI is the Syncthing relay server URI.
	// Format: relay://host:port/?id=DEVICE-ID
	// If empty, automatically discovers and uses the fastest available relay.
	RelayURI string

	// Dialer is an optional custom dialer for outgoing connections to the relay.
	// Use this to bind to a specific network interface or route traffic through a proxy.
	// If nil, standard net.Dialer is used.
	Dialer DialerFunc

	// ReconnectDelay is the delay between reconnection attempts.
	// Default: 500ms
	ReconnectDelay time.Duration

	// AllowedClientIDs is a list of Client Device IDs allowed to connect.
	// If this list is empty, the server allows ALL connections by default.
	// To restrict access, you must populate this list.
	AllowedClientIDs []string

	// AllowAnyClient explicitly disables client verification.
	// Since the default is already "Allow All" when AllowedClientIDs is empty,
	// this flag is mostly redundant but kept for clarity.
	AllowAnyClient bool

	// OnConnect is called when a new client connects.
	// Optional.
	OnConnect func(clientID string)

	// OnDisconnect is called when a client disconnects.
	// Optional.
	OnDisconnect func(clientID string)

	// OnRelayJoined is called when the server successfully connects to a relay.
	// It provides the relay address, the persistent Device ID, and the ID with the relay hint.
	// Optional but recommended.
	OnRelayJoined func(relayAddr, persistentID, deviceIDWithHint string)

	// Logger is a custom logger function.
	// If nil, logs are discarded.
	Logger func(level, message string)
}

// ClientConfig contains configuration options for a tunnel client.
type ClientConfig struct {
	// Identity is the client's identity for authentication.
	// Required.
	Identity Identity

	// TargetID is the device ID of the server to connect to.
	// Can be 43 chars (compact), 51 chars (compact+hint), 56 chars (standard), or 66 chars (standard+hint).
	// Required.
	TargetID string

	// ListenAddr is the local address to listen for connections on.
	// Default: "127.0.0.1:2222"
	// Ignored if Listener is set.
	ListenAddr string

	// Listener is an optional listener to accept connections from.
	// If provided, ListenAddr is ignored and this listener is used instead.
	Listener net.Listener

	// RelayURI is the Syncthing relay server URI.
	// Format: relay://host:port/?id=DEVICE-ID
	// If empty and TargetID contains a hint, uses the hinted relay.
	// If empty and no hint, automatically discovers relays.
	RelayURI string

	// Dialer is an optional custom dialer for outgoing connections to the relay.
	// Use this to bind to a specific network interface or route traffic through a proxy.
	// If nil, standard net.Dialer is used.
	Dialer DialerFunc

	// ReconnectDelay is the delay between reconnection attempts.
	// Default: 500ms
	ReconnectDelay time.Duration

	// OnTunnelEstablished is called when the tunnel is established.
	// Optional.
	OnTunnelEstablished func()

	// OnTunnelLost is called when the tunnel connection is lost.
	// Optional.
	OnTunnelLost func(err error)

	// Logger is a custom logger function.
	// If nil, logs are discarded.
	Logger func(level, message string)
}

func (c *ServerConfig) setDefaults() {
	if c.ForwardAddr == "" {
		c.ForwardAddr = "127.0.0.1:22"
	}
	if c.ReconnectDelay == 0 {
		c.ReconnectDelay = 500 * time.Millisecond
	}
}

func (c *ClientConfig) setDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:2222"
	}
	if c.ReconnectDelay == 0 {
		c.ReconnectDelay = 500 * time.Millisecond
	}
}
