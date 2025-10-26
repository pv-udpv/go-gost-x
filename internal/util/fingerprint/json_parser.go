package fingerprint

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// ClientHelloJSON represents the JSON structure from tls.peet.ws format
type ClientHelloJSON struct {
	TLS struct {
		Ciphers    []string        `json:"ciphers"`
		Extensions []ExtensionJSON `json:"extensions"`
		JA3        string          `json:"ja3"`
		JA3Hash    string          `json:"ja3_hash"`
		JA4        string          `json:"ja4"`
	} `json:"tls"`
	HTTPVersion string `json:"http_version"`
	UserAgent   string `json:"user_agent"`
}

// ExtensionJSON represents a TLS extension from the JSON
type ExtensionJSON struct {
	Name                       string   `json:"name"`
	Data                       string   `json:"data"`
	ServerName                 string   `json:"server_name"`
	EllipticCurvesPointFormats []string `json:"elliptic_curves_point_formats"`
	SupportedGroups            []string `json:"supported_groups"`
	Protocols                  []string `json:"protocols"` // ALPN
	Versions                   []string `json:"versions"`  // supported_versions
	SignatureAlgorithms        []string `json:"signature_algorithms"`
	StatusRequest              *struct {
		CertificateStatusType   string `json:"certificate_status_type"`
		ResponderIDListLength   int    `json:"responder_id_list_length"`
		RequestExtensionsLength int    `json:"request_extensions_length"`
	} `json:"status_request"`
	PSKKeyExchangeMode string              `json:"PSK_Key_Exchange_Mode"`
	SharedKeys         []map[string]string `json:"shared_keys"`
	PaddingDataLength  int                 `json:"padding_data_length"`
}

// ParseClientHelloJSON parses a JSON file in tls.peet.ws format and returns a ClientHelloSpec
func ParseClientHelloJSON(filePath string) (*utls.ClientHelloSpec, error) {
	// Try to get from cache first
	cacheKey, err := CacheKeyForFile(filePath)
	if err == nil {
		cache := GetGlobalCache()
		if cache != nil {
			if spec, found := cache.Get(cacheKey); found {
				return spec, nil
			}
		}
	}

	// Cache miss - parse the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClientHello JSON file: %w", err)
	}

	var chJSON ClientHelloJSON
	if err := json.Unmarshal(data, &chJSON); err != nil {
		return nil, fmt.Errorf("failed to parse ClientHello JSON: %w", err)
	}

	spec, err := BuildClientHelloSpecFromJSON(&chJSON)
	if err != nil {
		return nil, err
	}

	// Store in cache if we have a valid cache key
	if cacheKey != "" {
		cache := GetGlobalCache()
		if cache != nil {
			cache.Set(cacheKey, spec)
		}
	}

	return spec, nil
}

// BuildClientHelloSpecFromJSON converts the parsed JSON into a utls.ClientHelloSpec
func BuildClientHelloSpecFromJSON(chJSON *ClientHelloJSON) (*utls.ClientHelloSpec, error) {
	spec := &utls.ClientHelloSpec{
		TLSVersMin: utls.VersionTLS10,
		TLSVersMax: utls.VersionTLS13,
	}

	// Parse cipher suites
	var cipherSuites []uint16
	for _, cipherName := range chJSON.TLS.Ciphers {
		if cipherID := parseCipherSuiteName(cipherName); cipherID != 0 {
			cipherSuites = append(cipherSuites, cipherID)
		}
	}
	spec.CipherSuites = cipherSuites

	// Parse extensions
	var extensions []utls.TLSExtension
	var curves []utls.CurveID
	var alpnProtocols []string
	var serverName string

	for _, ext := range chJSON.TLS.Extensions {
		switch {
		case strings.Contains(ext.Name, "server_name"):
			serverName = ext.ServerName
			if serverName != "" {
				extensions = append(extensions, &utls.SNIExtension{ServerName: serverName})
			}

		case strings.Contains(ext.Name, "supported_groups"):
			for _, groupName := range ext.SupportedGroups {
				if curveID := parseSupportedGroup(groupName); curveID != 0 {
					curves = append(curves, curveID)
				}
			}
			extensions = append(extensions, &utls.SupportedCurvesExtension{Curves: curves})

		case strings.Contains(ext.Name, "ec_point_formats"):
			var formats []uint8
			for _, pf := range ext.EllipticCurvesPointFormats {
				if format := parsePointFormat(pf); format != 255 {
					formats = append(formats, format)
				}
			}
			extensions = append(extensions, &utls.SupportedPointsExtension{SupportedPoints: formats})

		case strings.Contains(ext.Name, "application_layer_protocol_negotiation"):
			alpnProtocols = ext.Protocols
			extensions = append(extensions, &utls.ALPNExtension{AlpnProtocols: alpnProtocols})

		case strings.Contains(ext.Name, "signature_algorithms"):
			var sigAlgos []utls.SignatureScheme
			for _, algoName := range ext.SignatureAlgorithms {
				if algo := parseSignatureAlgorithm(algoName); algo != 0 {
					sigAlgos = append(sigAlgos, algo)
				}
			}
			extensions = append(extensions, &utls.SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: sigAlgos,
			})

		case strings.Contains(ext.Name, "supported_versions"):
			var versions []uint16
			for _, verName := range ext.Versions {
				if ver := parseTLSVersion(verName); ver != 0 {
					versions = append(versions, ver)
				}
			}
			extensions = append(extensions, &utls.SupportedVersionsExtension{
				Versions: versions,
			})

		case strings.Contains(ext.Name, "key_share"):
			// Key share requires specific curve support
			if len(curves) > 0 {
				extensions = append(extensions, &utls.KeyShareExtension{
					KeyShares: []utls.KeyShare{},
				})
			}

		case strings.Contains(ext.Name, "psk_key_exchange_modes"):
			extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{
				Modes: []uint8{utls.PskModeDHE},
			})

		case strings.Contains(ext.Name, "session_ticket"):
			extensions = append(extensions, &utls.SessionTicketExtension{})

		case strings.Contains(ext.Name, "status_request"):
			extensions = append(extensions, &utls.StatusRequestExtension{})

		case strings.Contains(ext.Name, "signed_certificate_timestamp"):
			extensions = append(extensions, &utls.SCTExtension{})

		case strings.Contains(ext.Name, "extended_master_secret"):
			extensions = append(extensions, &utls.ExtendedMasterSecretExtension{})

		case strings.Contains(ext.Name, "renegotiation_info") || strings.Contains(ext.Name, "extensionRenegotiationInfo"):
			extensions = append(extensions, &utls.RenegotiationInfoExtension{
				Renegotiation: utls.RenegotiateOnceAsClient,
			})

		case strings.Contains(ext.Name, "padding"):
			if ext.PaddingDataLength > 0 {
				extensions = append(extensions, &utls.UtlsPaddingExtension{
					GetPaddingLen: utls.BoringPaddingStyle,
				})
			}
		}
	}

	spec.Extensions = extensions
	spec.CompressionMethods = []uint8{0} // No compression

	return spec, nil
}

// parseCipherSuiteName converts cipher suite name to ID
func parseCipherSuiteName(name string) uint16 {
	cipherMap := map[string]uint16{
		// TLS 1.3 cipher suites
		"TLS_AES_128_GCM_SHA256":       0x1301,
		"TLS_AES_256_GCM_SHA384":       0x1302,
		"TLS_CHACHA20_POLY1305_SHA256": 0x1303,
		"TLS_AES_128_CCM_SHA256":       0x1304,
		"TLS_AES_128_CCM_8_SHA256":     0x1305,

		// ECDHE-ECDSA cipher suites
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       0xc02b,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       0xc02c,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          0xc009,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          0xc00a,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256":       0xc023,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384":       0xc024,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,

		// ECDHE-RSA cipher suites
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":       0xc02f,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":       0xc030,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":          0xc013,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":          0xc014,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":       0xc027,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":       0xc028,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca8,

		// RSA cipher suites
		"TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009c,
		"TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009d,
		"TLS_RSA_WITH_AES_128_CBC_SHA":    0x002f,
		"TLS_RSA_WITH_AES_256_CBC_SHA":    0x0035,
		"TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003c,
		"TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003d,

		// DHE-RSA cipher suites
		"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256":       0x009e,
		"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384":       0x009f,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA":          0x0033,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA":          0x0039,
		"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256":       0x0067,
		"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256":       0x006b,
		"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xccaa,

		// Legacy cipher suites (for compatibility)
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA":         0x000a,
		"TLS_RSA_WITH_RC4_128_SHA":              0x0005,
		"TLS_RSA_WITH_RC4_128_MD5":              0x0004,
		"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA":   0xc012,
		"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA": 0xc008,

		// PSK cipher suites
		"TLS_PSK_WITH_AES_128_GCM_SHA256":             0x00a8,
		"TLS_PSK_WITH_AES_256_GCM_SHA384":             0x00a9,
		"TLS_PSK_WITH_AES_128_CBC_SHA256":             0x00ae,
		"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256":         0x00aa,
		"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384":         0x00ab,
		"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256":       0xc037,
		"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384":       0xc038,
		"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256": 0xccac,

		// ARIA cipher suites (Korean standard)
		"TLS_RSA_WITH_ARIA_128_GCM_SHA256":         0xc050,
		"TLS_RSA_WITH_ARIA_256_GCM_SHA384":         0xc051,
		"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256": 0xc05c,
		"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384": 0xc05d,
		"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256":   0xc060,
		"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384":   0xc061,
	}

	if id, ok := cipherMap[name]; ok {
		return id
	}
	return 0
}

// parseSupportedGroup converts group name to curve ID
func parseSupportedGroup(name string) utls.CurveID {
	groupMap := map[string]utls.CurveID{
		"X25519 (29)": utls.X25519,
		"P-256 (23)":  utls.CurveP256,
		"P-384 (24)":  utls.CurveP384,
		"P-521 (25)":  utls.CurveP521,
	}

	// Try exact match first
	if curve, ok := groupMap[name]; ok {
		return curve
	}

	// Try extracting ID from parentheses
	if idx := strings.Index(name, "("); idx != -1 {
		if endIdx := strings.Index(name[idx:], ")"); endIdx != -1 {
			idStr := strings.TrimSpace(name[idx+1 : idx+endIdx])
			if id, err := strconv.Atoi(idStr); err == nil {
				return utls.CurveID(id)
			}
		}
	}

	return 0
}

// parsePointFormat converts point format string to uint8
func parsePointFormat(pf string) uint8 {
	// Point formats: uncompressed (0), ansiX962_compressed_prime (1), ansiX962_compressed_char2 (2)
	pf = strings.TrimPrefix(pf, "0x")
	if val, err := strconv.ParseUint(pf, 16, 8); err == nil {
		return uint8(val)
	}
	return 255 // Invalid
}

// parseSignatureAlgorithm converts signature algorithm name to scheme
func parseSignatureAlgorithm(name string) utls.SignatureScheme {
	algoMap := map[string]utls.SignatureScheme{
		"ecdsa_secp256r1_sha256": utls.ECDSAWithP256AndSHA256,
		"ecdsa_secp384r1_sha384": utls.ECDSAWithP384AndSHA384,
		"ecdsa_secp521r1_sha512": utls.ECDSAWithP521AndSHA512,
		"rsa_pss_rsae_sha256":    utls.PSSWithSHA256,
		"rsa_pss_rsae_sha384":    utls.PSSWithSHA384,
		"rsa_pss_rsae_sha512":    utls.PSSWithSHA512,
		"rsa_pkcs1_sha256":       utls.PKCS1WithSHA256,
		"rsa_pkcs1_sha384":       utls.PKCS1WithSHA384,
		"rsa_pkcs1_sha512":       utls.PKCS1WithSHA512,
		"rsa_pkcs1_sha1":         utls.PKCS1WithSHA1,
	}

	if algo, ok := algoMap[name]; ok {
		return algo
	}
	return 0
}

// parseTLSVersion converts version string to uint16
func parseTLSVersion(ver string) uint16 {
	versionMap := map[string]uint16{
		"TLS 1.3": utls.VersionTLS13,
		"TLS 1.2": utls.VersionTLS12,
		"TLS 1.1": utls.VersionTLS11,
		"TLS 1.0": utls.VersionTLS10,
	}

	if v, ok := versionMap[ver]; ok {
		return v
	}
	return 0
}

// GetJA3FromJSON extracts the JA3 string from the JSON file if available
func GetJA3FromJSON(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read JSON file: %w", err)
	}

	var chJSON ClientHelloJSON
	if err := json.Unmarshal(data, &chJSON); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	return chJSON.TLS.JA3, nil
}

// GetJA4FromJSON extracts the JA4 string from the JSON file if available
func GetJA4FromJSON(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to read JSON file: %w", err)
	}

	var chJSON ClientHelloJSON
	if err := json.Unmarshal(data, &chJSON); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	return chJSON.TLS.JA4, nil
}
