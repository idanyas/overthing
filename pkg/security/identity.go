package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"tunnel/pkg/logging"
)

// Fixed timestamp for deterministic certificate generation
var deterministicCertTime = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// IMPORTANT - COMPACT ID ENCODING - DO NOT MODIFY:
// Compact Device IDs use a CUSTOM Base63 encoding with the alphabet:
//   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_
//
// This is NOT standard base64. It uses exactly 63 characters (no - or . or ~).
// 32 bytes encode to exactly 43 characters.
//
// DEVELOPERS: You MUST preserve this exact encoding. Changing it will break
// all existing device IDs and identity files.
const compactAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
const compactEncodedLen = 43 // Length of encoded 32-byte value in base63

var big63 = big.NewInt(63)
var bigZero = big.NewInt(0)

// encodeBase63 encodes bytes to base63 string using compactAlphabet
func encodeBase63(data []byte) string {
	num := new(big.Int).SetBytes(data)
	mod := new(big.Int)

	result := make([]byte, 0, compactEncodedLen)
	for num.Cmp(bigZero) > 0 {
		num.DivMod(num, big63, mod)
		result = append(result, compactAlphabet[mod.Int64()])
	}

	// Pad with leading 'A' (represents 0) to reach expected length
	for len(result) < compactEncodedLen {
		result = append(result, 'A')
	}

	// Reverse the result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

// decodeBase63 decodes base63 string to bytes
func decodeBase63(s string) ([]byte, error) {
	if len(s) != compactEncodedLen {
		return nil, fmt.Errorf("invalid length: expected %d, got %d", compactEncodedLen, len(s))
	}

	num := new(big.Int)
	for _, c := range s {
		idx := strings.IndexRune(compactAlphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid character: %c", c)
		}
		num.Mul(num, big63)
		num.Add(num, big.NewInt(int64(idx)))
	}

	// Convert to 32 bytes, left-padding with zeros if needed
	bytes := num.Bytes()
	if len(bytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(bytes):], bytes)
		bytes = padded
	}
	if len(bytes) > 32 {
		return nil, fmt.Errorf("decoded value too large")
	}

	return bytes, nil
}

// LoadOrGenerateIdentity loads an identity from file, or generates and saves a new one
func LoadOrGenerateIdentity(path string) (tls.Certificate, string, string) {
	if path == "" {
		logging.Info("Using ephemeral identity (not saved)")
		return GenerateIdentity()
	}

	cert, isCompact, err := LoadIdentity(path)
	if err == nil {
		fullID := GetDeviceID(cert.Certificate[0])
		compactID := GetDeviceIDCompact(cert.Certificate[0])

		if isCompact {
			logging.Info("Loaded identity from %s", path)
		} else {
			logging.Info("Loaded identity from %s (PEM format)", path)
		}

		return cert, fullID, compactID
	}

	// Generate new identity
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		logging.Fatal("Failed to generate random seed: %v", err)
	}

	cert, fullID, compactID := GenerateIdentityFromSeed(seed)

	if err := SaveIdentityCompact(path, seed); err != nil {
		logging.Warn("Failed to save identity to %s: %v", path, err)
	} else {
		logging.OK("Generated new identity, saved to %s", path)
	}

	return cert, fullID, compactID
}

// LoadIdentity loads identity from file (supports compact and PEM formats)
func LoadIdentity(path string) (tls.Certificate, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, false, err
	}

	content := strings.TrimSpace(string(data))

	// Compact format: 43 chars base63 = 32 bytes seed
	if len(content) == compactEncodedLen {
		seed, err := decodeBase63(content)
		if err == nil && len(seed) == 32 {
			cert, _, _ := GenerateIdentityFromSeed(seed)
			return cert, true, nil
		}
	}

	// PEM format fallback
	cert, err := loadIdentityPEM(data)
	return cert, false, err
}

func loadIdentityPEM(data []byte) (tls.Certificate, error) {
	var certPEM, keyPEM []byte
	rest := data
	for {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certPEM = pem.EncodeToMemory(block)
		case "PRIVATE KEY", "ED25519 PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			keyPEM = pem.EncodeToMemory(block)
		}
		rest = r
	}

	if certPEM == nil || keyPEM == nil {
		return tls.Certificate{}, fmt.Errorf("missing certificate or private key")
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

// SaveIdentityCompact saves the 32-byte seed as 43-char base63 format
func SaveIdentityCompact(path string, seed []byte) error {
	encoded := encodeBase63(seed)
	return os.WriteFile(path, []byte(encoded+"\n"), 0600)
}

// GenerateIdentity creates a new Ed25519-based identity
func GenerateIdentity() (tls.Certificate, string, string) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		logging.Fatal("Failed to generate random seed: %v", err)
	}
	return GenerateIdentityFromSeed(seed)
}

// GenerateIdentityFromSeed creates a deterministic identity from a 32-byte seed
func GenerateIdentityFromSeed(seed []byte) (tls.Certificate, string, string) {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    deterministicCertTime,
		NotAfter:     deterministicCertTime.Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey, privateKey)
	if err != nil {
		logging.Fatal("Failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	fullID := GetDeviceID(certDER)
	compactID := GetDeviceIDCompact(certDER)

	return cert, fullID, compactID
}

// GetDeviceID returns the full Syncthing-format Device ID (56 chars, no dashes)
func GetDeviceID(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])

	var result strings.Builder
	result.Grow(56)

	for i := 0; i < 4; i++ {
		chunk := encoded[i*13 : i*13+13]
		result.WriteString(chunk)
		result.WriteRune(luhn32CheckDigit(chunk))
	}

	return result.String()
}

// GetDeviceIDCompact returns the compact Device ID (43 chars base63)
func GetDeviceIDCompact(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return encodeBase63(hash[:])
}

// DeviceIDFromString parses device ID from compact (43 chars) or Syncthing (56 chars) format
func DeviceIDFromString(id string) ([]byte, error) {
	id = strings.TrimSpace(id)

	// Try compact format first: 43 chars base63 = 32 bytes
	if len(id) == compactEncodedLen {
		decoded, err := decodeBase63(id)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	// Syncthing format: 56 chars with Luhn checksums (with optional dashes)
	noDashes := strings.ReplaceAll(id, "-", "")
	normalized := NormalizeID(noDashes)
	if len(normalized) == 56 {
		return DeviceIDToBytes(normalized)
	}

	return nil, fmt.Errorf("invalid device ID: expected 43-char compact or 56-char full format")
}

func luhn32CheckDigit(s string) rune {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	factor := 1
	sum := 0

	for _, r := range s {
		codepoint := strings.IndexRune(alphabet, r)
		if codepoint == -1 {
			continue
		}

		addend := factor * codepoint
		if factor == 2 {
			factor = 1
		} else {
			factor = 2
		}

		addend = (addend / 32) + (addend % 32)
		sum += addend
	}

	remainder := sum % 32
	checkCodepoint := (32 - remainder) % 32
	return rune(alphabet[checkCodepoint])
}

// DeviceIDToBytes converts Syncthing format Device ID to raw 32 bytes
func DeviceIDToBytes(id string) ([]byte, error) {
	id = NormalizeID(id)

	if len(id) != 56 {
		return nil, fmt.Errorf("invalid Device ID length: %d", len(id))
	}

	base32Str := id[0:13] + id[14:27] + id[28:41] + id[42:55]
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(base32Str)
	if err != nil {
		return nil, fmt.Errorf("base32 decode failed: %w", err)
	}

	if len(decoded) != 32 {
		return nil, fmt.Errorf("decoded length mismatch: expected 32, got %d", len(decoded))
	}

	return decoded, nil
}

// NormalizeID removes dashes and converts to uppercase
func NormalizeID(id string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", ""))
}

// BytesToDeviceID converts raw 32-byte device ID to Syncthing format (no dashes)
func BytesToDeviceID(raw []byte) string {
	if len(raw) != 32 {
		return ""
	}

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)

	var result strings.Builder
	result.Grow(56)

	for i := 0; i < 4; i++ {
		chunk := encoded[i*13 : i*13+13]
		result.WriteString(chunk)
		result.WriteRune(luhn32CheckDigit(chunk))
	}

	return result.String()
}

// BytesToCompactID converts raw 32-byte device ID to compact base63 format
func BytesToCompactID(raw []byte) string {
	return encodeBase63(raw)
}

// GetDeviceIDBytes computes the SHA-256 hash of the cert DER
func GetDeviceIDBytes(certDER []byte) []byte {
	hash := sha256.Sum256(certDER)
	return hash[:]
}
