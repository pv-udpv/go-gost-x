package ja3

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// JA3Data holds parsed JA3 fingerprint components
type JA3Data struct {
	Version            uint16
	CipherSuites       []uint16
	Extensions         []uint16
	SupportedGroups    []uint16
	EllipticCurvePoint []uint8
}

// ClientHelloSpecFile represents the JSON structure from TLS fingerprint services
type ClientHelloSpecFile struct {
	TLS struct {
		Ciphers    []string `json:"ciphers"`
		Extensions []struct {
			Name                       string              `json:"name"`
			Data                       string              `json:"data,omitempty"`
			ServerName                 string              `json:"server_name,omitempty"`
			EllipticCurvesPointFormats []string            `json:"elliptic_curves_point_formats,omitempty"`
			SupportedGroups            []string            `json:"supported_groups,omitempty"`
			Protocols                  []string            `json:"protocols,omitempty"`
			SignatureAlgorithms        []string            `json:"signature_algorithms,omitempty"`
			Versions                   []string            `json:"versions,omitempty"`
			PSKKeyExchangeMode         string              `json:"PSK_Key_Exchange_Mode,omitempty"`
			PaddingDataLength          int                 `json:"padding_data_length,omitempty"`
			StatusRequest              *struct{}           `json:"status_request,omitempty"`
			MasterSecretData           string              `json:"master_secret_data,omitempty"`
			ExtendedMasterSecretData   string              `json:"extended_master_secret_data,omitempty"`
			SharedKeys                 []map[string]string `json:"shared_keys,omitempty"`
		} `json:"extensions"`
		JA3                  string `json:"ja3"`
		JA3Hash              string `json:"ja3_hash"`
		JA4                  string `json:"ja4"`
		TLSVersionRecord     string `json:"tls_version_record"`
		TLSVersionNegotiated string `json:"tls_version_negotiated"`
	} `json:"tls"`
}

// ParseJA3 parses a JA3 fingerprint string
// Format: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
// Example: "771,4865-4866-4867-49195-49199,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
func ParseJA3(ja3 string) (*JA3Data, error) {
	parts := strings.Split(ja3, ",")
	if len(parts) != 5 {
		return nil, fmt.Errorf("invalid JA3 format: expected 5 parts, got %d", len(parts))
	}

	data := &JA3Data{}

	// Parse SSL version
	if parts[0] != "" {
		v, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid SSL version: %w", err)
		}
		data.Version = uint16(v)
	}

	// Parse cipher suites
	if parts[1] != "" {
		ciphers := strings.Split(parts[1], "-")
		for _, c := range ciphers {
			v, err := strconv.ParseUint(c, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid cipher suite %s: %w", c, err)
			}
			data.CipherSuites = append(data.CipherSuites, uint16(v))
		}
	}

	// Parse extensions
	if parts[2] != "" {
		exts := strings.Split(parts[2], "-")
		for _, e := range exts {
			v, err := strconv.ParseUint(e, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid extension %s: %w", e, err)
			}
			data.Extensions = append(data.Extensions, uint16(v))
		}
	}

	// Parse elliptic curves (supported groups)
	if parts[3] != "" {
		curves := strings.Split(parts[3], "-")
		for _, curve := range curves {
			v, err := strconv.ParseUint(curve, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("invalid elliptic curve %s: %w", curve, err)
			}
			data.SupportedGroups = append(data.SupportedGroups, uint16(v))
		}
	}

	// Parse elliptic curve point formats
	if parts[4] != "" {
		points := strings.Split(parts[4], "-")
		for _, p := range points {
			v, err := strconv.ParseUint(p, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid point format %s: %w", p, err)
			}
			data.EllipticCurvePoint = append(data.EllipticCurvePoint, uint8(v))
		}
	}

	return data, nil
}

// LoadClientHelloSpecFromFile loads a ClientHello spec from a JSON file
func LoadClientHelloSpecFromFile(filename string) (*ClientHelloSpecFile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	var spec ClientHelloSpecFile
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &spec, nil
}

// ParseCipherName converts cipher name to cipher suite ID
func ParseCipherName(name string) (uint16, error) {
	cipherMap := map[string]uint16{
		"TLS_AES_128_GCM_SHA256":                        0x1301,
		"TLS_AES_256_GCM_SHA384":                        0x1302,
		"TLS_CHACHA20_POLY1305_SHA256":                  0x1303,
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       0xc02b,
		"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         0xc02f,
		"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       0xc02c,
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         0xc030,
		"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xcca9,
		"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   0xcca8,
		"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":            0xc013,
		"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":            0xc014,
		"TLS_RSA_WITH_AES_128_GCM_SHA256":               0x009c,
		"TLS_RSA_WITH_AES_256_GCM_SHA384":               0x009d,
		"TLS_RSA_WITH_AES_128_CBC_SHA":                  0x002f,
		"TLS_RSA_WITH_AES_256_CBC_SHA":                  0x0035,
		"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":          0xc009,
		"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":          0xc00a,
	}

	if id, ok := cipherMap[name]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("unknown cipher: %s", name)
}

// ParseSupportedGroup converts group name to group ID
func ParseSupportedGroup(name string) (uint16, error) {
	// Extract the numeric ID from the name format "X25519 (29)" or just name
	if idx := strings.Index(name, "("); idx > 0 {
		endIdx := strings.Index(name, ")")
		if endIdx > idx {
			numStr := strings.TrimSpace(name[idx+1 : endIdx])
			v, err := strconv.ParseUint(numStr, 10, 16)
			if err == nil {
				return uint16(v), nil
			}
		}
	}

	groupMap := map[string]uint16{
		"X25519":    29,
		"P-256":     23,
		"P-384":     24,
		"P-521":     25,
		"secp256r1": 23,
		"secp384r1": 24,
		"secp521r1": 25,
		"x25519":    29,
	}

	normalizedName := strings.TrimSpace(name)
	if id, ok := groupMap[normalizedName]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("unknown supported group: %s", name)
}

// ParseSignatureAlgorithm converts signature algorithm name to ID
func ParseSignatureAlgorithm(name string) (uint16, error) {
	sigAlgMap := map[string]uint16{
		"rsa_pkcs1_sha256":       0x0401,
		"rsa_pkcs1_sha384":       0x0501,
		"rsa_pkcs1_sha512":       0x0601,
		"ecdsa_secp256r1_sha256": 0x0403,
		"ecdsa_secp384r1_sha384": 0x0503,
		"ecdsa_secp521r1_sha512": 0x0603,
		"rsa_pss_rsae_sha256":    0x0804,
		"rsa_pss_rsae_sha384":    0x0805,
		"rsa_pss_rsae_sha512":    0x0806,
		"ed25519":                0x0807,
		"rsa_pss_pss_sha256":     0x0809,
		"rsa_pss_pss_sha384":     0x080a,
		"rsa_pss_pss_sha512":     0x080b,
	}

	if id, ok := sigAlgMap[name]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("unknown signature algorithm: %s", name)
}

// ParseTLSVersion converts TLS version string to version ID
func ParseTLSVersion(version string) (uint16, error) {
	versionMap := map[string]uint16{
		"TLS 1.0": 0x0301,
		"TLS 1.1": 0x0302,
		"TLS 1.2": 0x0303,
		"TLS 1.3": 0x0304,
		"SSL 3.0": 0x0300,
	}

	if id, ok := versionMap[version]; ok {
		return id, nil
	}

	// Try numeric
	v, err := strconv.ParseUint(version, 10, 16)
	if err == nil {
		return uint16(v), nil
	}

	return 0, fmt.Errorf("unknown TLS version: %s", version)
}
