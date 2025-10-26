package ja3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JA4Fingerprint represents a parsed JA4 fingerprint
// Format: a_b_c where:
// a = QUIC/TCP + TLS version + SNI presence + cipher count + extension count
// b = First 12 chars of SHA256 hash of cipher suites
// c = First 12 chars of SHA256 hash of extensions (sorted)
type JA4Fingerprint struct {
	// Protocol: "q" for QUIC, "t" for TCP
	Protocol string

	// TLS Version: "10" for 1.0, "11" for 1.1, "12" for 1.2, "13" for 1.3
	TLSVersion string

	// SNI: "d" if domain SNI present, "i" if IP/missing
	SNI string

	// CipherCount: 2-digit hex count of cipher suites
	CipherCount string

	// ExtensionCount: 2-digit hex count of extensions
	ExtensionCount string

	// CipherHash: First 12 chars of SHA256 hash of cipher suite values (original order)
	CipherHash string

	// ExtensionHash: First 12 chars of SHA256 hash of extension IDs (sorted, ignoring SNI/ALPN)
	ExtensionHash string

	// Raw data for advanced processing
	RawCipherSuites []uint16
	RawExtensions   []uint16
	HasSNI          bool
	ALPNProtocols   []string
}

// JA4Data holds components needed to generate JA4 fingerprint
type JA4Data struct {
	IsQUIC          bool
	TLSVersion      uint16
	ServerName      string
	CipherSuites    []uint16
	Extensions      []uint16
	ALPNProtocols   []string
	SupportedGroups []uint16
}

// String returns the JA4 fingerprint in "a_b_c" format
func (j *JA4Fingerprint) String() string {
	partA := fmt.Sprintf("%s%s%s%s%s",
		j.Protocol,
		j.TLSVersion,
		j.SNI,
		j.CipherCount,
		j.ExtensionCount,
	)

	return fmt.Sprintf("%s_%s_%s", partA, j.CipherHash, j.ExtensionHash)
}

// GenerateJA4 creates a JA4 fingerprint from JA4Data
func GenerateJA4(data *JA4Data) (*JA4Fingerprint, error) {
	if data == nil {
		return nil, fmt.Errorf("JA4Data cannot be nil")
	}

	fp := &JA4Fingerprint{
		RawCipherSuites: data.CipherSuites,
		RawExtensions:   data.Extensions,
		HasSNI:          data.ServerName != "",
		ALPNProtocols:   data.ALPNProtocols,
	}

	// Protocol: "q" for QUIC, "t" for TCP
	if data.IsQUIC {
		fp.Protocol = "q"
	} else {
		fp.Protocol = "t"
	}

	// TLS Version
	fp.TLSVersion = formatTLSVersion(data.TLSVersion)

	// SNI: "d" for domain, "i" for IP or missing
	fp.SNI = determineSNIType(data.ServerName)

	// Cipher Count (2-digit hex)
	cipherCount := len(data.CipherSuites)
	if cipherCount > 255 {
		cipherCount = 255 // Cap at max 2-digit hex
	}
	fp.CipherCount = fmt.Sprintf("%02x", cipherCount)

	// Extension Count (2-digit hex)
	extCount := len(data.Extensions)
	if extCount > 255 {
		extCount = 255
	}
	fp.ExtensionCount = fmt.Sprintf("%02x", extCount)

	// Cipher Hash: SHA256 of cipher suites in ORIGINAL order
	fp.CipherHash = generateCipherHash(data.CipherSuites)

	// Extension Hash: SHA256 of extensions in SORTED order (excluding SNI=0 and ALPN=16)
	fp.ExtensionHash = generateExtensionHash(data.Extensions)

	return fp, nil
}

// ParseJA4String parses a JA4 fingerprint string "a_b_c"
func ParseJA4String(ja4String string) (*JA4Fingerprint, error) {
	parts := strings.Split(ja4String, "_")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JA4 format: expected 'a_b_c', got %d parts", len(parts))
	}

	partA := parts[0]
	if len(partA) < 7 {
		return nil, fmt.Errorf("invalid JA4 part A: too short (got %d chars, need at least 7)", len(partA))
	}

	fp := &JA4Fingerprint{
		Protocol:       string(partA[0]),
		TLSVersion:     partA[1:3],
		SNI:            string(partA[3]),
		CipherCount:    partA[4:6],
		ExtensionCount: partA[6:8],
		CipherHash:     parts[1],
		ExtensionHash:  parts[2],
	}

	// Validate protocol
	if fp.Protocol != "q" && fp.Protocol != "t" {
		return nil, fmt.Errorf("invalid protocol: must be 'q' or 't', got '%s'", fp.Protocol)
	}

	// Validate TLS version
	validVersions := map[string]bool{"10": true, "11": true, "12": true, "13": true, "00": true}
	if !validVersions[fp.TLSVersion] {
		return nil, fmt.Errorf("invalid TLS version: %s", fp.TLSVersion)
	}

	// Validate SNI
	if fp.SNI != "d" && fp.SNI != "i" {
		return nil, fmt.Errorf("invalid SNI indicator: must be 'd' or 'i', got '%s'", fp.SNI)
	}

	// Validate hash lengths
	if len(fp.CipherHash) != 12 {
		return nil, fmt.Errorf("invalid cipher hash length: expected 12, got %d", len(fp.CipherHash))
	}
	if len(fp.ExtensionHash) != 12 {
		return nil, fmt.Errorf("invalid extension hash length: expected 12, got %d", len(fp.ExtensionHash))
	}

	return fp, nil
}

// ConvertJA3ToJA4 converts JA3Data to JA4Data for fingerprint generation
func ConvertJA3ToJA4(ja3Data *JA3Data, serverName string, isQUIC bool) *JA4Data {
	return &JA4Data{
		IsQUIC:       isQUIC,
		TLSVersion:   ja3Data.Version,
		ServerName:   serverName,
		CipherSuites: ja3Data.CipherSuites,
		Extensions:   ja3Data.Extensions,
		// Note: ALPN protocols need to be extracted separately from ClientHello
		SupportedGroups: ja3Data.SupportedGroups,
	}
}

// formatTLSVersion converts TLS version number to JA4 format
func formatTLSVersion(version uint16) string {
	switch version {
	case 0x0300: // SSL 3.0
		return "s3"
	case 0x0301: // TLS 1.0
		return "10"
	case 0x0302: // TLS 1.1
		return "11"
	case 0x0303: // TLS 1.2
		return "12"
	case 0x0304: // TLS 1.3
		return "13"
	default:
		return "00" // Unknown
	}
}

// determineSNIType returns "d" if domain SNI is present, "i" otherwise
func determineSNIType(serverName string) string {
	if serverName == "" {
		return "i"
	}

	// Check if it's an IPv4 address (only digits and dots)
	isIPv4 := true
	for _, c := range serverName {
		if !((c >= '0' && c <= '9') || c == '.') {
			isIPv4 = false
			break
		}
	}
	if isIPv4 {
		return "i"
	}

	// Check if it's an IPv6 address (contains colons and only hex digits)
	hasColon := false
	allHexOrColon := true
	for _, c := range serverName {
		if c == ':' {
			hasColon = true
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			allHexOrColon = false
			break
		}
	}
	if hasColon && allHexOrColon {
		return "i" // IPv6
	}

	// Otherwise, it's a domain name
	return "d"
}

// generateCipherHash creates the first 12 chars of SHA256 hash of cipher suites
// Cipher suites are in ORIGINAL order (not sorted)
func generateCipherHash(cipherSuites []uint16) string {
	if len(cipherSuites) == 0 {
		// Return hash of empty string
		hash := sha256.Sum256([]byte{})
		return hex.EncodeToString(hash[:])[:12]
	}

	// Convert cipher suites to comma-separated string
	var parts []string
	for _, cipher := range cipherSuites {
		parts = append(parts, fmt.Sprintf("%04x", cipher))
	}
	cipherString := strings.Join(parts, ",")

	// SHA256 hash
	hash := sha256.Sum256([]byte(cipherString))
	return hex.EncodeToString(hash[:])[:12]
}

// generateExtensionHash creates the first 12 chars of SHA256 hash of extensions
// Extensions are SORTED and SNI (0) and ALPN (16) are excluded
func generateExtensionHash(extensions []uint16) string {
	if len(extensions) == 0 {
		hash := sha256.Sum256([]byte{})
		return hex.EncodeToString(hash[:])[:12]
	}

	// Filter out SNI (0) and ALPN (16), then sort
	var filtered []uint16
	for _, ext := range extensions {
		if ext != 0 && ext != 16 {
			filtered = append(filtered, ext)
		}
	}

	// Sort extensions
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i] < filtered[j]
	})

	if len(filtered) == 0 {
		hash := sha256.Sum256([]byte{})
		return hex.EncodeToString(hash[:])[:12]
	}

	// Convert to comma-separated string
	var parts []string
	for _, ext := range filtered {
		parts = append(parts, fmt.Sprintf("%04x", ext))
	}
	extString := strings.Join(parts, ",")

	// SHA256 hash
	hash := sha256.Sum256([]byte(extString))
	return hex.EncodeToString(hash[:])[:12]
}

// GetJA4FromClientHelloFile generates JA4 from ClientHelloSpecFile
func GetJA4FromClientHelloFile(file *ClientHelloSpecFile, isQUIC bool) (*JA4Fingerprint, error) {
	if file == nil {
		return nil, fmt.Errorf("ClientHelloSpecFile cannot be nil")
	}

	// If JA4 already present in file, parse and return it
	if file.TLS.JA4 != "" {
		return ParseJA4String(file.TLS.JA4)
	}

	// Otherwise, generate from components
	ja4Data := &JA4Data{
		IsQUIC: isQUIC,
	}

	// Parse TLS version
	if file.TLS.TLSVersionNegotiated != "" {
		if version, err := parseTLSVersionString(file.TLS.TLSVersionNegotiated); err == nil {
			ja4Data.TLSVersion = version
		}
	}

	// Parse cipher suites
	for _, cipher := range file.TLS.Ciphers {
		if cipherID := parseCipherSuiteString(cipher); cipherID != 0 {
			ja4Data.CipherSuites = append(ja4Data.CipherSuites, cipherID)
		}
	}

	// Parse extensions and extract SNI/ALPN
	for _, ext := range file.TLS.Extensions {
		extID := extensionNameToID(ext.Name)
		if extID != 0 {
			ja4Data.Extensions = append(ja4Data.Extensions, extID)
		}

		// Extract SNI
		if ext.Name == "server_name" && ext.ServerName != "" {
			ja4Data.ServerName = ext.ServerName
		}

		// Extract ALPN
		if ext.Name == "application_layer_protocol_negotiation" {
			ja4Data.ALPNProtocols = ext.Protocols
		}
	}

	return GenerateJA4(ja4Data)
}

// parseTLSVersionString converts TLS version string to uint16
func parseTLSVersionString(version string) (uint16, error) {
	version = strings.TrimSpace(strings.ToUpper(version))
	switch {
	case strings.Contains(version, "1.3"):
		return 0x0304, nil
	case strings.Contains(version, "1.2"):
		return 0x0303, nil
	case strings.Contains(version, "1.1"):
		return 0x0302, nil
	case strings.Contains(version, "1.0"):
		return 0x0301, nil
	default:
		// Try to parse hex format like "0x0303"
		if strings.HasPrefix(version, "0X") {
			if val, err := strconv.ParseUint(version[2:], 16, 16); err == nil {
				return uint16(val), nil
			}
		}
		return 0, fmt.Errorf("unknown TLS version: %s", version)
	}
}

// parseCipherSuiteString converts cipher suite name to ID
func parseCipherSuiteString(name string) uint16 {
	// This is a simplified version - full implementation would use the mapping from parser.go
	name = strings.TrimSpace(strings.ToUpper(name))

	// Try hex format first
	if strings.HasPrefix(name, "0X") {
		if val, err := strconv.ParseUint(name[2:], 16, 16); err == nil {
			return uint16(val)
		}
	}

	// Map common cipher suite names to IDs
	commonCiphers := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                  0x1301,
		"TLS_AES_256_GCM_SHA384":                  0x1302,
		"TLS_CHACHA20_POLY1305_SHA256":            0x1303,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   0xC02F,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   0xC030,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
	}

	if id, ok := commonCiphers[name]; ok {
		return id
	}

	return 0
}

// extensionNameToID converts extension name to ID
func extensionNameToID(name string) uint16 {
	name = strings.ToLower(strings.TrimSpace(name))

	extensionMap := map[string]uint16{
		"server_name":                            0,
		"max_fragment_length":                    1,
		"status_request":                         5,
		"supported_groups":                       10,
		"ec_point_formats":                       11,
		"signature_algorithms":                   13,
		"application_layer_protocol_negotiation": 16,
		"signed_certificate_timestamp":           18,
		"padding":                                21,
		"extended_master_secret":                 23,
		"session_ticket":                         35,
		"supported_versions":                     43,
		"psk_key_exchange_modes":                 45,
		"key_share":                              51,
		"renegotiation_info":                     65281,
	}

	if id, ok := extensionMap[name]; ok {
		return id
	}

	return 0
}
