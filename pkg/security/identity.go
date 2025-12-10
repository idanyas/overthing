package security

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"tunnel/pkg/logging"
)

// IMPORTANT - COMPACT ID ENCODING - DO NOT MODIFY:
const compactAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
const compactEncodedLen = 43
const standardIDLen = 56

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

	for len(result) < compactEncodedLen {
		result = append(result, 'A')
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}

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

// JoinRelayHint appends encoded IP:Port to the Device ID.
// Supports both Compact (43 chars) and Standard (56 chars) IDs.
// Compact uses Base63 suffix (8 chars). Standard uses Base32 suffix (10 chars).
func JoinRelayHint(id string, ip net.IP, port int) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return id
	}

	// Pack IP (4 bytes) + Port (2 bytes) = 6 bytes
	buf := make([]byte, 6)
	copy(buf[0:4], ip4)
	binary.BigEndian.PutUint16(buf[4:6], uint16(port))

	// Compact ID Logic (Base63)
	if len(id) == compactEncodedLen {
		// 6 bytes -> 8 chars Base63
		var val uint64
		val = uint64(buf[0])<<40 | uint64(buf[1])<<32 | uint64(buf[2])<<24 | uint64(buf[3])<<16 | uint64(buf[4])<<8 | uint64(buf[5])

		out := make([]byte, 8)
		for i := 7; i >= 0; i-- {
			out[i] = compactAlphabet[val%63]
			val /= 63
		}
		return id + string(out)
	}

	// Standard ID Logic (Base32)
	// We normalize first to ensure no dashes for length check, 
	// but usually we want to preserve the input format.
	// However, if it is a valid ID (with or without dashes), we append Base32.
	
	cleanID := strings.ReplaceAll(id, "-", "")
	if len(cleanID) == standardIDLen {
		// 6 bytes -> 10 chars Base32
		suffix := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		return id + suffix
	}

	return id
}

// SplitRelayHint tries to extract IP:Port from a Device ID.
// Returns the cleaned ID, IP, Port, and a boolean indicating success.
func SplitRelayHint(s string) (cleanID string, ip net.IP, port int, ok bool) {
	// 1. Check Compact + Hint (43 + 8 = 51)
	if len(s) == compactEncodedLen+8 {
		cleanID = s[:compactEncodedLen]
		suffix := s[compactEncodedLen:]

		// Decode Base63
		var val uint64
		for i := 0; i < 8; i++ {
			idx := strings.IndexByte(compactAlphabet, suffix[i])
			if idx < 0 {
				return s, nil, 0, false
			}
			val = val*63 + uint64(idx)
		}
		return decodePackedIPPort(cleanID, val)
	}

	// 2. Check Standard + Hint (Standard can have dashes)
	// Standard length without dashes is 56. Hint is 10 chars (Base32).
	// Total clean length = 66.
	
	noDashes := strings.ReplaceAll(s, "-", "")
	if len(noDashes) == standardIDLen+10 {
		// Determine where the split is in the original string
		// Since dashes are only in the first part, we can take the last 10 chars.
		suffix := s[len(s)-10:]
		cleanID = s[:len(s)-10]
		
		buf, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(suffix)
		if err != nil || len(buf) != 6 {
			return s, nil, 0, false
		}
		
		val := uint64(buf[0])<<40 | uint64(buf[1])<<32 | uint64(buf[2])<<24 | uint64(buf[3])<<16 | uint64(buf[4])<<8 | uint64(buf[5])
		return decodePackedIPPort(cleanID, val)
	}

	return s, nil, 0, false
}

func decodePackedIPPort(cleanID string, val uint64) (string, net.IP, int, bool) {
	ipBytes := make([]byte, 4)
	ipBytes[0] = byte(val >> 40)
	ipBytes[1] = byte(val >> 32)
	ipBytes[2] = byte(val >> 24)
	ipBytes[3] = byte(val >> 16)
	port := int(val & 0xFFFF)
	return cleanID, net.IP(ipBytes), port, true
}

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

func LoadIdentity(path string) (tls.Certificate, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, false, err
	}

	content := strings.TrimSpace(string(data))
	if len(content) == compactEncodedLen {
		seed, err := decodeBase63(content)
		if err == nil && len(seed) == 32 {
			cert, _, _ := GenerateIdentityFromSeed(seed)
			return cert, true, nil
		}
	}

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

func SaveIdentityCompact(path string, seed []byte) error {
	encoded := encodeBase63(seed)
	return os.WriteFile(path, []byte(encoded+"\n"), 0600)
}

func GenerateIdentity() (tls.Certificate, string, string) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		logging.Fatal("Failed to generate random seed: %v", err)
	}
	return GenerateIdentityFromSeed(seed)
}

func GenerateIdentityFromSeed(seed []byte) (tls.Certificate, string, string) {
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	epoch := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    epoch,
		NotAfter:     epoch.Add(20 * 365 * 24 * time.Hour), 
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

func GetDeviceIDCompact(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return encodeBase63(hash[:])
}

func DeviceIDFromString(id string) ([]byte, error) {
	id = strings.TrimSpace(id)
	
	// Handle Hint stripping
	if cleanID, _, _, ok := SplitRelayHint(id); ok {
		id = cleanID
	}

	if len(id) == compactEncodedLen {
		decoded, err := decodeBase63(id)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	noDashes := strings.ReplaceAll(id, "-", "")
	normalized := NormalizeID(noDashes)
	if len(normalized) == 56 {
		return DeviceIDToBytes(normalized)
	}

	return nil, fmt.Errorf("invalid device ID")
}

func luhn32CheckDigit(s string) rune {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	
	factor := 1
	sum := 0

	for i := len(s) - 1; i >= 0; i-- {
		codepoint := strings.IndexByte(alphabet, s[i])
		if codepoint == -1 {
			continue 
		}

		addend := factor * codepoint
		addend = (addend / 32) + (addend % 32)
		sum += addend

		if factor == 2 {
			factor = 1
		} else {
			factor = 2
		}
	}

	remainder := sum % 32
	checkCodepoint := (32 - remainder) % 32
	return rune(alphabet[checkCodepoint])
}

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
		return nil, fmt.Errorf("decoded length mismatch")
	}
	return decoded, nil
}

func NormalizeID(id string) string {
	return strings.ToUpper(strings.ReplaceAll(id, "-", ""))
}

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

func BytesToCompactID(raw []byte) string {
	return encodeBase63(raw)
}

func GetDeviceIDBytes(certDER []byte) []byte {
	hash := sha256.Sum256(certDER)
	return hash[:]
}
