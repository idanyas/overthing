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
// Supports both Compact and Standard IDs, and IPv4/IPv6.
func JoinRelayHint(id string, ip net.IP, port int) string {
	var buf []byte
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4: 4 bytes + 2 bytes = 6 bytes
		buf = make([]byte, 6)
		copy(buf[0:4], ip4)
		binary.BigEndian.PutUint16(buf[4:6], uint16(port))
	} else {
		// IPv6: 16 bytes + 2 bytes = 18 bytes
		buf = make([]byte, 18)
		copy(buf[0:16], ip)
		binary.BigEndian.PutUint16(buf[16:18], uint16(port))
	}

	// Compact ID Logic (Base63)
	if len(id) == compactEncodedLen {
		// Convert buffer to Big Int then to Base63
		num := new(big.Int).SetBytes(buf)
		mod := new(big.Int)
		var out []byte

		// Encode to Base63
		for num.Cmp(bigZero) > 0 {
			num.DivMod(num, big63, mod)
			out = append(out, compactAlphabet[mod.Int64()])
		}

		targetLen := 8
		if len(buf) > 6 {
			targetLen = 25
		}

		for len(out) < targetLen {
			out = append(out, 'A')
		}

		// Reverse
		for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
			out[i], out[j] = out[j], out[i]
		}

		return id + string(out)
	}

	// Standard ID Logic (Base32)
	cleanID := strings.ReplaceAll(id, "-", "")
	if len(cleanID) == standardIDLen {
		suffix := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf)
		return id + suffix
	}

	return id
}

// SplitRelayHint tries to extract IP:Port from a Device ID.
func SplitRelayHint(s string) (cleanID string, ip net.IP, port int, ok bool) {
	// 1. Compact + Hint
	if len(s) > compactEncodedLen && strings.HasPrefix(s, s[:compactEncodedLen]) {
		suffix := s[compactEncodedLen:]

		// We expect length 8 (IPv4) or 25 (IPv6)
		if len(suffix) == 8 || len(suffix) == 25 {
			cleanID = s[:compactEncodedLen]

			// Decode Base63
			num := new(big.Int)
			for _, c := range suffix {
				idx := strings.IndexRune(compactAlphabet, c)
				if idx < 0 {
					goto StandardCheck
				}
				num.Mul(num, big63)
				num.Add(num, big.NewInt(int64(idx)))
			}

			buf := num.Bytes()
			// Pad back to 6 or 18 bytes if leading zeros were dropped
			if len(suffix) == 8 && len(buf) < 6 {
				padded := make([]byte, 6)
				copy(padded[6-len(buf):], buf)
				buf = padded
			} else if len(suffix) == 25 && len(buf) < 18 {
				padded := make([]byte, 18)
				copy(padded[18-len(buf):], buf)
				buf = padded
			}

			if len(buf) == 6 {
				return decodePackedIPPort(cleanID, buf)
			} else if len(buf) == 18 {
				return decodePackedIPPort(cleanID, buf)
			}
		}
	}

StandardCheck:
	// 2. Standard + Hint
	noDashes := strings.ReplaceAll(s, "-", "")

	if len(noDashes) == standardIDLen+10 || len(noDashes) == standardIDLen+29 {
		hintLen := len(noDashes) - standardIDLen
		suffix := s[len(s)-hintLen:] // works because dashes are only in the ID part
		cleanID = s[:len(s)-hintLen]

		buf, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(suffix)
		if err == nil && (len(buf) == 6 || len(buf) == 18) {
			return decodePackedIPPort(cleanID, buf)
		}
	}

	return s, nil, 0, false
}

func decodePackedIPPort(cleanID string, buf []byte) (string, net.IP, int, bool) {
	if len(buf) == 6 {
		ip := net.IP(buf[0:4])
		port := int(binary.BigEndian.Uint16(buf[4:6]))
		return cleanID, ip, port, true
	} else if len(buf) == 18 {
		ip := net.IP(buf[0:16])
		port := int(binary.BigEndian.Uint16(buf[16:18]))
		return cleanID, ip, port, true
	}
	return cleanID, nil, 0, false
}

func LoadOrGenerateIdentity(path string) (tls.Certificate, string, string, error) {
	if path == "" {
		return GenerateIdentity()
	}

	cert, _, err := LoadIdentity(path)
	if err == nil {
		fullID := GetDeviceID(cert.Certificate[0])
		compactID := GetDeviceIDCompact(cert.Certificate[0])
		return cert, fullID, compactID, nil
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return tls.Certificate{}, "", "", fmt.Errorf("failed to generate random seed: %w", err)
	}

	cert, fullID, compactID, err := GenerateIdentityFromSeed(seed)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}

	if err := SaveIdentityCompact(path, seed); err != nil {
		return tls.Certificate{}, "", "", fmt.Errorf("failed to save identity to %s: %w", path, err)
	}

	return cert, fullID, compactID, nil
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
			cert, _, _, err := GenerateIdentityFromSeed(seed)
			if err != nil {
				return tls.Certificate{}, true, err
			}
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

func GenerateIdentity() (tls.Certificate, string, string, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return tls.Certificate{}, "", "", fmt.Errorf("failed to generate random seed: %w", err)
	}
	return GenerateIdentityFromSeed(seed)
}

func GenerateIdentityFromSeed(seed []byte) (tls.Certificate, string, string, error) {
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
		return tls.Certificate{}, "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	fullID := GetDeviceID(certDER)
	compactID := GetDeviceIDCompact(certDER)

	return cert, fullID, compactID, nil
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

	// Compact ID
	if len(id) == compactEncodedLen {
		decoded, err := decodeBase63(id)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	// Standard ID - Validate Checksums
	noDashes := strings.ReplaceAll(id, "-", "")
	normalized := NormalizeID(noDashes)

	if len(normalized) == 56 {
		// Validate Luhn Checksums
		for i := 0; i < 4; i++ {
			chunk := normalized[i*14 : i*14+13] // The 13 data chars
			check := rune(normalized[i*14+13])  // The 14th char is check digit
			if luhn32CheckDigit(chunk) != check {
				return nil, fmt.Errorf("invalid checksum in device ID group %d", i+1)
			}
		}
		return DeviceIDToBytes(normalized)
	}

	return nil, fmt.Errorf("invalid device ID")
}

func luhn32CheckDigit(s string) rune {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

	factor := 1
	sum := 0

	// FIX: Iterate forward, not backward
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

func DeviceIDToBytes(id string) ([]byte, error) {
	id = NormalizeID(id)
	if len(id) != 56 {
		return nil, fmt.Errorf("invalid Device ID length: %d", len(id))
	}
	// Extract data parts skipping check digits
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
