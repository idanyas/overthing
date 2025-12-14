// Package tunnel provides a multiplexed TCP tunnel over Syncthing relays.
//
// This package allows you to create secure, NAT-traversing TCP tunnels between
// two endpoints using the Syncthing relay network. It supports both client and
// server modes, with automatic reconnection and connection multiplexing via yamux.
//
// Basic usage as a server:
//
//	identity, _ := tunnel.LoadOrGenerateIdentity("~/.tunnel-key")
//	server := tunnel.NewServer(tunnel.ServerConfig{
//	    Identity:    identity,
//	    ForwardAddr: "127.0.0.1:22",
//	})
//	server.Run(context.Background())
//
// Basic usage as a client:
//
//	identity, _ := tunnel.LoadOrGenerateIdentity("~/.tunnel-key")
//	client := tunnel.NewClient(tunnel.ClientConfig{
//	    Identity:   identity,
//	    TargetID:   "DEVICE-ID-HERE",
//	    ListenAddr: "127.0.0.1:2222",
//	})
//	client.Run(context.Background())
package tunnel

import (
	"crypto/tls"
	"fmt"

	"github.com/idanyas/overthing/pkg/security"
)

// Version is the current version of the tunnel library.
const Version = "1.4.0"

// DefaultRelayURI is the default relay URI. An empty string signals that the
// library should automatically discover and use the fastest available Syncthing
// relay from the public relay pool.
const DefaultRelayURI = ""

// Identity represents a tunnel endpoint identity containing the TLS certificate
// and derived device IDs.
type Identity struct {
	// Certificate is the TLS certificate used for authentication.
	Certificate tls.Certificate

	// FullID is the 56-character Syncthing-format device ID.
	FullID string

	// CompactID is the 43-character base64url-encoded device ID.
	CompactID string
}

// GenerateIdentity creates a new random Ed25519-based identity.
// The identity is ephemeral and not persisted to disk.
func GenerateIdentity() Identity {
	cert, fullID, compactID, err := security.GenerateIdentity()
	if err != nil {
		panic(fmt.Sprintf("tunnel: failed to generate identity: %v", err))
	}
	return Identity{
		Certificate: cert,
		FullID:      fullID,
		CompactID:   compactID,
	}
}

// LoadOrGenerateIdentity loads an identity from the specified path, or generates
// a new one and saves it if the file doesn't exist. If path is empty, an ephemeral
// identity is generated without saving.
//
// The identity file format is a 43-character base64url-encoded Ed25519 seed.
// Legacy PEM format files are also supported for reading.
func LoadOrGenerateIdentity(path string) (Identity, error) {
	cert, fullID, compactID, err := security.LoadOrGenerateIdentity(path)
	if err != nil {
		return Identity{}, err
	}
	return Identity{
		Certificate: cert,
		FullID:      fullID,
		CompactID:   compactID,
	}, nil
}

// LoadIdentity loads an existing identity from the specified path.
// Returns an error if the file doesn't exist or is invalid.
func LoadIdentity(path string) (Identity, error) {
	cert, _, err := security.LoadIdentity(path)
	if err != nil {
		return Identity{}, err
	}
	fullID := security.GetDeviceID(cert.Certificate[0])
	compactID := security.GetDeviceIDCompact(cert.Certificate[0])
	return Identity{
		Certificate: cert,
		FullID:      fullID,
		CompactID:   compactID,
	}, nil
}

// ParseDeviceID parses a device ID from either compact (43 chars) or
// Syncthing (56 chars with optional dashes) format.
func ParseDeviceID(id string) ([]byte, error) {
	return security.DeviceIDFromString(id)
}

// DeviceIDToString converts raw device ID bytes to Syncthing format.
func DeviceIDToString(id []byte) string {
	return security.BytesToDeviceID(id)
}

// DeviceIDToCompact converts raw device ID bytes to compact base64url format.
func DeviceIDToCompact(id []byte) string {
	return security.BytesToCompactID(id)
}
