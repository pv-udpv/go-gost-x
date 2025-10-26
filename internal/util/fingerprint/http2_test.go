package fingerprint

import (
	"testing"
)

func TestGenerateHTTP2Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint *HTTP2Fingerprint
		expected    string
	}{
		{
			name: "Chrome fingerprint",
			fingerprint: &HTTP2Fingerprint{
				Settings: map[uint16]uint32{
					1: 65536,
					2: 0,
					3: 100,
					4: 6291456,
					6: 262144,
				},
				WindowUpdate:      15663105,
				Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
				PseudoHeaderOrder: "m,a,s,p",
			},
			expected: "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		{
			name: "Firefox fingerprint",
			fingerprint: &HTTP2Fingerprint{
				Settings: map[uint16]uint32{
					1: 65536,
					2: 0,
					4: 131072,
					5: 16384,
				},
				WindowUpdate:      12517377,
				Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: false},
				PseudoHeaderOrder: "m,p,a,s",
			},
			expected: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		},
		{
			name: "Safari fingerprint",
			fingerprint: &HTTP2Fingerprint{
				Settings: map[uint16]uint32{
					2: 0,
					3: 100,
					4: 6291456,
					6: 262144,
				},
				WindowUpdate:      15663105,
				Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
				PseudoHeaderOrder: "m,a,s,p",
			},
			expected: "2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GenerateHTTP2Fingerprint(tt.fingerprint)
			if result != tt.expected {
				t.Errorf("GenerateHTTP2Fingerprint() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseHTTP2Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
		wantErr     bool
		checkFunc   func(*HTTP2Fingerprint) bool
	}{
		{
			name:        "Valid Chrome fingerprint",
			fingerprint: "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
			wantErr:     false,
			checkFunc: func(fp *HTTP2Fingerprint) bool {
				return fp.Settings[1] == 65536 &&
					fp.Settings[2] == 0 &&
					fp.Settings[3] == 100 &&
					fp.Settings[4] == 6291456 &&
					fp.Settings[6] == 262144 &&
					fp.WindowUpdate == 15663105 &&
					fp.PseudoHeaderOrder == "m,a,s,p"
			},
		},
		{
			name:        "Valid Firefox fingerprint",
			fingerprint: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
			wantErr:     false,
			checkFunc: func(fp *HTTP2Fingerprint) bool {
				return fp.Settings[1] == 65536 &&
					fp.Settings[4] == 131072 &&
					fp.Settings[5] == 16384 &&
					fp.WindowUpdate == 12517377 &&
					fp.PseudoHeaderOrder == "m,p,a,s"
			},
		},
		{
			name:        "Invalid format - missing parts",
			fingerprint: "1:65536;2:0|15663105",
			wantErr:     true,
		},
		{
			name:        "Invalid format - empty",
			fingerprint: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp, err := ParseHTTP2Fingerprint(tt.fingerprint)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHTTP2Fingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkFunc != nil && !tt.checkFunc(fp) {
				t.Errorf("ParseHTTP2Fingerprint() validation failed for %v", tt.name)
			}
		})
	}
}

func TestGetHTTP2Profile(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		wantOk      bool
		checkName   string
	}{
		{
			name:        "Chrome 120 profile",
			profileName: "chrome_120",
			wantOk:      true,
			checkName:   "Chrome 120",
		},
		{
			name:        "Firefox 120 profile",
			profileName: "firefox_120",
			wantOk:      true,
			checkName:   "Firefox 120",
		},
		{
			name:        "Safari 17 profile",
			profileName: "safari_17",
			wantOk:      true,
			checkName:   "Safari 17",
		},
		{
			name:        "Non-existent profile",
			profileName: "nonexistent",
			wantOk:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, ok := GetHTTP2Profile(tt.profileName)
			if ok != tt.wantOk {
				t.Errorf("GetHTTP2Profile() ok = %v, want %v", ok, tt.wantOk)
			}
			if ok && profile.Name != tt.checkName {
				t.Errorf("GetHTTP2Profile() name = %v, want %v", profile.Name, tt.checkName)
			}
		})
	}
}

func TestGetHTTP2Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		expected    string
	}{
		{
			name:        "Chrome fingerprint",
			profileName: "chrome_120",
			expected:    "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		{
			name:        "Firefox fingerprint",
			profileName: "firefox_120",
			expected:    "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		},
		{
			name:        "Non-existent profile",
			profileName: "nonexistent",
			expected:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetHTTP2Fingerprint(tt.profileName)
			if result != tt.expected {
				t.Errorf("GetHTTP2Fingerprint() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestListHTTP2Profiles(t *testing.T) {
	profiles := ListHTTP2Profiles()
	if len(profiles) != len(HTTP2ProfilesDB) {
		t.Errorf("ListHTTP2Profiles() returned %d profiles, want %d", len(profiles), len(HTTP2ProfilesDB))
	}

	// Check that profiles are sorted
	for i := 1; i < len(profiles); i++ {
		if profiles[i-1] >= profiles[i] {
			t.Errorf("ListHTTP2Profiles() not sorted: %s >= %s", profiles[i-1], profiles[i])
		}
	}
}

func TestGenerateHTTP2FingerprintHash(t *testing.T) {
	tests := []struct {
		name        string
		fingerprint string
	}{
		{
			name:        "Chrome fingerprint",
			fingerprint: "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		},
		{
			name:        "Firefox fingerprint",
			fingerprint: "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := GenerateHTTP2FingerprintHash(tt.fingerprint)
			if len(hash) != 64 { // SHA256 produces 64 hex characters
				t.Errorf("GenerateHTTP2FingerprintHash() hash length = %d, want 64", len(hash))
			}
			// Hash should be deterministic
			hash2 := GenerateHTTP2FingerprintHash(tt.fingerprint)
			if hash != hash2 {
				t.Errorf("GenerateHTTP2FingerprintHash() not deterministic")
			}
		})
	}
}

func TestHTTP2ProfileCount(t *testing.T) {
	// Verify we have all 28 profiles
	expectedProfiles := []string{
		"chrome_120", "chrome_108",
		"firefox_120", "firefox_102",
		"safari_17", "safari_ios_17", "safari_ipad",
		"edge_120", "edge_mobile",
		"android_chrome",
		"brave_browser",
		"samsung_internet",
		"firefox_android",
		"opera_gx", "opera_mobile",
		"vivaldi",
		"tor_browser",
		"yandex_browser",
		"uc_browser",
		"whale_browser",
		"duckduckgo_browser",
		"ecosia_browser",
		"maxthon_browser",
		"curl_latest",
		"go_http",
		"okhttp_android",
	}

	for _, name := range expectedProfiles {
		if _, ok := HTTP2ProfilesDB[name]; !ok {
			t.Errorf("Missing expected profile: %s", name)
		}
	}

	if len(HTTP2ProfilesDB) < len(expectedProfiles) {
		t.Errorf("HTTP2ProfilesDB has %d profiles, expected at least %d", len(HTTP2ProfilesDB), len(expectedProfiles))
	}
}

func TestHTTP2PseudoHeaderOrders(t *testing.T) {
	// Test that different browser families have correct pseudo-header orders
	tests := []struct {
		profile       string
		expectedOrder string
	}{
		{"chrome_120", "m,a,s,p"},
		{"firefox_120", "m,p,a,s"},
		{"safari_17", "m,a,s,p"},
		{"edge_120", "m,a,s,p"},
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			profile, ok := GetHTTP2Profile(tt.profile)
			if !ok {
				t.Fatalf("Profile %s not found", tt.profile)
			}
			if profile.PseudoHeaderOrder != tt.expectedOrder {
				t.Errorf("Profile %s has pseudo-header order %s, want %s",
					tt.profile, profile.PseudoHeaderOrder, tt.expectedOrder)
			}
		})
	}
}

func BenchmarkGenerateHTTP2Fingerprint(b *testing.B) {
	fp := &HTTP2Fingerprint{
		Settings: map[uint16]uint32{
			1: 65536,
			2: 0,
			3: 100,
			4: 6291456,
			6: 262144,
		},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		PseudoHeaderOrder: "m,a,s,p",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GenerateHTTP2Fingerprint(fp)
	}
}

func BenchmarkParseHTTP2Fingerprint(b *testing.B) {
	fingerprint := "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseHTTP2Fingerprint(fingerprint)
	}
}

func BenchmarkGetHTTP2Profile(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetHTTP2Profile("chrome_120")
	}
}
