package tunnel

import (
	"net"
	"time"
)

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

	// ReconnectDelay is the delay between reconnection attempts.
	// Default: 500ms
	ReconnectDelay time.Duration

	// AllowedClientIDs is a list of Client Device IDs allowed to connect.
	// If AllowAnyClient is false, clients not in this list are rejected.
	AllowedClientIDs []string

	// AllowAnyClient disables client verification.
	// WARNING: This allows anyone to access the forwarded port.
	AllowAnyClient bool

	// OnConnect is called when a new client connects.
	// Optional.
	OnConnect func(clientID string)

	// OnDisconnect is called when a client disconnects.
	// Optional.
	OnDisconnect func(clientID string)

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
	// If empty, automatically discovers and uses the fastest available relay.
	RelayURI string

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
	// RelayURI intentionally not defaulted - will be auto-discovered if empty
	if c.ReconnectDelay == 0 {
		c.ReconnectDelay = 500 * time.Millisecond
	}
}

func (c *ClientConfig) setDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = "127.0.0.1:2222"
	}
	// RelayURI intentionally not defaulted - will be auto-discovered if empty
	if c.ReconnectDelay == 0 {
		c.ReconnectDelay = 500 * time.Millisecond
	}
}
