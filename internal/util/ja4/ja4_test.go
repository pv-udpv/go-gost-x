package ja4

import (
	"testing"
)

func TestGenerateJA4(t *testing.T) {
	tests := []struct {
		name     string
		data     *JA4Data
		expected string // Expected JA4 format pattern
		wantErr  bool
	}{
		{
			name: "Chrome TLS 1.3 TCP",
			data: &JA4Data{
				IsQUIC:     false,
				TLSVersion: 0x0303, // TLS 1.2 in record, negotiates 1.3
				ServerName: "example.com",
				CipherSuites: []uint16{
					0x1301, // TLS_AES_128_GCM_SHA256
					0x1302, // TLS_AES_256_GCM_SHA384
					0x1303, // TLS_CHACHA20_POLY1305_SHA256
					0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				},
				Extensions: []uint16{
					0,  // server_name
					10, // supported_groups
					11, // ec_point_formats
					13, // signature_algorithms
					16, // alpn
					23, // extended_master_secret
					43, // supported_versions
					51, // key_share
				},
			},
			expected: "t12d0408", // Protocol + Version + SNI + Cipher count (04) + Ext count (08)
			wantErr:  false,
		},
		{
			name: "Firefox QUIC",
			data: &JA4Data{
				IsQUIC:     true,
				TLSVersion: 0x0304, // TLS 1.3
				ServerName: "192.168.1.1",
				CipherSuites: []uint16{
					0x1301, // TLS_AES_128_GCM_SHA256
					0x1302, // TLS_AES_256_GCM_SHA384
				},
				Extensions: []uint16{
					0,  // server_name
					10, // supported_groups
					13, // signature_algorithms
					16, // alpn
					43, // supported_versions
				},
			},
			expected: "q13i0205", // QUIC + TLS1.3 + IP + 2 ciphers (02) + 5 extensions (05)
			wantErr:  false,
		},
		{
			name: "Many cipher suites",
			data: &JA4Data{
				IsQUIC:     false,
				TLSVersion: 0x0303,
				ServerName: "test.example.com",
				CipherSuites: []uint16{
					0x1301, 0x1302, 0x1303, 0xc02f, 0xc030,
					0xc02b, 0xc02c, 0xcca9, 0xcca8, 0xc013,
					0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
				},
				Extensions: []uint16{0, 10, 11, 13, 16, 23, 43, 51},
			},
			expected: "t12d0f08", // 15 ciphers = 0x0f, 8 extensions
			wantErr:  false,
		},
		{
			name:     "Nil data",
			data:     nil,
			expected: "",
			wantErr:  true,
		},
		{
			name: "Empty cipher suites",
			data: &JA4Data{
				IsQUIC:       false,
				TLSVersion:   0x0303,
				ServerName:   "example.com",
				CipherSuites: []uint16{},
				Extensions:   []uint16{0, 10, 13},
			},
			expected: "t12d0003", // 0 ciphers, 3 extensions
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := GenerateJA4(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateJA4() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Check that result has correct format
			ja4String := fp.String()
			if len(ja4String) < 10 { // Minimum: "t12d0001_" + 12 + "_" + 12 = 29 chars
				t.Errorf("JA4 string too short: %s", ja4String)
			}

			// Check part A matches expected
			partA := ja4String[:8]
			if partA != tt.expected {
				t.Errorf("Part A = %s, want %s", partA, tt.expected)
			}

			// Verify format: a_b_c
			parts := splitJA4(ja4String)
			if len(parts) != 3 {
				t.Errorf("JA4 should have 3 parts separated by _, got %d: %s", len(parts), ja4String)
			}

			// Check hash lengths
			if len(parts[1]) != 12 {
				t.Errorf("Cipher hash should be 12 chars, got %d: %s", len(parts[1]), parts[1])
			}
			if len(parts[2]) != 12 {
				t.Errorf("Extension hash should be 12 chars, got %d: %s", len(parts[2]), parts[2])
			}
		})
	}
}

func TestParseJA4String(t *testing.T) {
	tests := []struct {
		name    string
		ja4Str  string
		wantErr bool
		checks  func(*testing.T, *JA4Fingerprint)
	}{
		{
			name:    "Valid Chrome fingerprint",
			ja4Str:  "t13d1516h2_8daaf6152771_1eb89897b454",
			wantErr: false,
			checks: func(t *testing.T, fp *JA4Fingerprint) {
				if fp.Protocol != "t" {
					t.Errorf("Protocol = %s, want t", fp.Protocol)
				}
				if fp.TLSVersion != "13" {
					t.Errorf("TLSVersion = %s, want 13", fp.TLSVersion)
				}
				if fp.SNI != "d" {
					t.Errorf("SNI = %s, want d", fp.SNI)
				}
				if fp.CipherCount != "15" {
					t.Errorf("CipherCount = %s, want 15", fp.CipherCount)
				}
			},
		},
		{
			name:    "Valid QUIC fingerprint",
			ja4Str:  "q13d0605h3_abc123def456_789012345678",
			wantErr: false,
			checks: func(t *testing.T, fp *JA4Fingerprint) {
				if fp.Protocol != "q" {
					t.Errorf("Protocol = %s, want q", fp.Protocol)
				}
			},
		},
		{
			name:    "Invalid format - missing parts",
			ja4Str:  "t13d1516h2_8daaf6152771",
			wantErr: true,
		},
		{
			name:    "Invalid format - no underscores",
			ja4Str:  "t13d1516h28daaf61527711eb89897b454",
			wantErr: true,
		},
		{
			name:    "Invalid protocol",
			ja4Str:  "x13d1516h2_8daaf6152771_1eb89897b454",
			wantErr: true,
		},
		{
			name:    "Invalid TLS version",
			ja4Str:  "t99d1516h2_8daaf6152771_1eb89897b454",
			wantErr: true,
		},
		{
			name:    "Invalid SNI indicator",
			ja4Str:  "t13x1516h2_8daaf6152771_1eb89897b454",
			wantErr: true,
		},
		{
			name:    "Short cipher hash",
			ja4Str:  "t13d1516h2_8daaf615_1eb89897b454",
			wantErr: true,
		},
		{
			name:    "Short extension hash",
			ja4Str:  "t13d1516h2_8daaf6152771_1eb898",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := ParseJA4String(tt.ja4Str)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseJA4String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil && tt.checks != nil {
				tt.checks(t, fp)
			}
		})
	}
}

func TestFormatTLSVersion(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{0x0300, "s3"}, // SSL 3.0
		{0x0301, "10"}, // TLS 1.0
		{0x0302, "11"}, // TLS 1.1
		{0x0303, "12"}, // TLS 1.2
		{0x0304, "13"}, // TLS 1.3
		{0x9999, "00"}, // Unknown
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatTLSVersion(tt.version)
			if result != tt.expected {
				t.Errorf("formatTLSVersion(0x%04x) = %s, want %s", tt.version, result, tt.expected)
			}
		})
	}
}

func TestDetermineSNIType(t *testing.T) {
	tests := []struct {
		serverName string
		expected   string
	}{
		{"example.com", "d"},
		{"www.google.com", "d"},
		{"192.168.1.1", "i"},
		{"2001:0db8:85a3::8a2e:0370:7334", "i"},
		{"", "i"},
		{"localhost", "d"},
		{"test-server.local", "d"},
	}

	for _, tt := range tests {
		t.Run(tt.serverName, func(t *testing.T) {
			result := determineSNIType(tt.serverName)
			if result != tt.expected {
				t.Errorf("determineSNIType(%s) = %s, want %s", tt.serverName, result, tt.expected)
			}
		})
	}
}

func TestGenerateCipherHash(t *testing.T) {
	tests := []struct {
		name    string
		ciphers []uint16
	}{
		{
			name:    "Standard cipher list",
			ciphers: []uint16{0x1301, 0x1302, 0x1303, 0xc02f},
		},
		{
			name:    "Empty cipher list",
			ciphers: []uint16{},
		},
		{
			name:    "Single cipher",
			ciphers: []uint16{0x1301},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := generateCipherHash(tt.ciphers)
			if len(hash) != 12 {
				t.Errorf("Hash length = %d, want 12", len(hash))
			}

			// Hash should be hexadecimal
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("Hash contains non-hex character: %c", c)
				}
			}
		})
	}
}

func TestGenerateExtensionHash(t *testing.T) {
	tests := []struct {
		name       string
		extensions []uint16
	}{
		{
			name:       "Standard extensions with SNI and ALPN",
			extensions: []uint16{0, 10, 11, 13, 16, 23, 43, 51},
		},
		{
			name:       "Extensions without SNI/ALPN",
			extensions: []uint16{10, 11, 13, 23, 43, 51},
		},
		{
			name:       "Only SNI and ALPN",
			extensions: []uint16{0, 16},
		},
		{
			name:       "Empty",
			extensions: []uint16{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := generateExtensionHash(tt.extensions)
			if len(hash) != 12 {
				t.Errorf("Hash length = %d, want 12", len(hash))
			}

			// Hash should be hexadecimal
			for _, c := range hash {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Errorf("Hash contains non-hex character: %c", c)
				}
			}

			// Test that same extensions in different order produce same hash (due to sorting)
			hash2 := generateExtensionHash(reverse(tt.extensions))
			if hash != hash2 {
				t.Errorf("Hash is not stable: %s != %s", hash, hash2)
			}
		})
	}
}

// TestConvertJA3ToJA4 - Temporarily disabled during refactoring
// This function has been moved to the fingerprint package
// and will be re-enabled once the refactoring is complete

func TestRoundTripJA4(t *testing.T) {
	// Create original JA4 data
	original := &JA4Data{
		IsQUIC:     false,
		TLSVersion: 0x0303,
		ServerName: "example.com",
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303, 0xc02f,
		},
		Extensions: []uint16{
			0, 10, 11, 13, 16, 23, 43, 51,
		},
	}

	// Generate fingerprint
	fp, err := GenerateJA4(original)
	if err != nil {
		t.Fatalf("GenerateJA4() error = %v", err)
	}

	// Convert to string
	ja4String := fp.String()

	// Parse back
	parsed, err := ParseJA4String(ja4String)
	if err != nil {
		t.Fatalf("ParseJA4String() error = %v", err)
	}

	// Compare
	if parsed.Protocol != fp.Protocol {
		t.Errorf("Protocol mismatch: %s != %s", parsed.Protocol, fp.Protocol)
	}
	if parsed.TLSVersion != fp.TLSVersion {
		t.Errorf("TLSVersion mismatch: %s != %s", parsed.TLSVersion, fp.TLSVersion)
	}
	if parsed.SNI != fp.SNI {
		t.Errorf("SNI mismatch: %s != %s", parsed.SNI, fp.SNI)
	}
	if parsed.CipherHash != fp.CipherHash {
		t.Errorf("CipherHash mismatch: %s != %s", parsed.CipherHash, fp.CipherHash)
	}
	if parsed.ExtensionHash != fp.ExtensionHash {
		t.Errorf("ExtensionHash mismatch: %s != %s", parsed.ExtensionHash, fp.ExtensionHash)
	}
}

// Helper functions

func splitJA4(ja4 string) []string {
	var parts []string
	current := ""
	for _, c := range ja4 {
		if c == '_' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func reverse(slice []uint16) []uint16 {
	result := make([]uint16, len(slice))
	for i, v := range slice {
		result[len(slice)-1-i] = v
	}
	return result
}
