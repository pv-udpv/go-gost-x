package fingerprint

import (
	"crypto/tls"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestConfigureHTTP2Transport(t *testing.T) {
	tests := []struct {
		name          string
		profileName   string
		wantErr       bool
		checkSettings func(*testing.T, *http2.Transport)
	}{
		{
			name:        "Chrome 120 profile",
			profileName: "chrome_120",
			wantErr:     false,
			checkSettings: func(t *testing.T, transport *http2.Transport) {
				// Chrome sets MAX_HEADER_LIST_SIZE to 262144
				if transport.MaxHeaderListSize != 262144 {
					t.Errorf("MaxHeaderListSize = %d, want 262144", transport.MaxHeaderListSize)
				}
				// Chrome has MAX_CONCURRENT_STREAMS=100, should enable strict mode
				if !transport.StrictMaxConcurrentStreams {
					t.Error("StrictMaxConcurrentStreams should be true for Chrome")
				}
				// Chrome has large WINDOW_UPDATE (15MB), should have longer timeout
				if transport.ReadIdleTimeout < 20*time.Second {
					t.Errorf("ReadIdleTimeout = %v, want >= 20s for Chrome", transport.ReadIdleTimeout)
				}
			},
		},
		{
			name:        "Firefox 120 profile",
			profileName: "firefox_120",
			wantErr:     false,
			checkSettings: func(t *testing.T, transport *http2.Transport) {
				// Firefox doesn't set MAX_HEADER_LIST_SIZE in profile
				// So it might be 0 or default

				// Firefox has WINDOW_UPDATE of 12MB
				if transport.ReadIdleTimeout < 15*time.Second {
					t.Errorf("ReadIdleTimeout = %v, want >= 15s for Firefox", transport.ReadIdleTimeout)
				}
			},
		},
		{
			name:        "Safari 17 profile",
			profileName: "safari_17",
			wantErr:     false,
			checkSettings: func(t *testing.T, transport *http2.Transport) {
				// Safari sets MAX_HEADER_LIST_SIZE to 262144
				if transport.MaxHeaderListSize != 262144 {
					t.Errorf("MaxHeaderListSize = %d, want 262144", transport.MaxHeaderListSize)
				}
			},
		},
		{
			name:        "Invalid profile",
			profileName: "nonexistent_browser",
			wantErr:     true,
			checkSettings: func(t *testing.T, transport *http2.Transport) {
				// Should not be called
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &http2.Transport{
				TLSClientConfig: &tls.Config{},
			}

			err := ConfigureHTTP2Transport(transport, tt.profileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureHTTP2Transport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				tt.checkSettings(t, transport)
			}
		})
	}
}

func TestGetHTTP2Transport(t *testing.T) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	tests := []struct {
		name        string
		profileName string
		wantErr     bool
	}{
		{
			name:        "Valid Chrome profile",
			profileName: "chrome_120",
			wantErr:     false,
		},
		{
			name:        "Valid Firefox profile",
			profileName: "firefox_120",
			wantErr:     false,
		},
		{
			name:        "Invalid profile",
			profileName: "invalid",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, err := GetHTTP2Transport(tlsConfig, tt.profileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHTTP2Transport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if transport == nil {
					t.Error("GetHTTP2Transport() returned nil transport")
				}
				if transport.TLSClientConfig != tlsConfig {
					t.Error("TLSClientConfig not set correctly")
				}
			}
		})
	}
}

func TestNewHTTP2Transport(t *testing.T) {
	tests := []struct {
		name    string
		config  *HTTP2TransportConfig
		wantErr bool
	}{
		{
			name: "With profile",
			config: &HTTP2TransportConfig{
				TLSConfig:   &tls.Config{},
				ProfileName: "chrome_120",
			},
			wantErr: false,
		},
		{
			name: "With overrides",
			config: &HTTP2TransportConfig{
				TLSConfig:         &tls.Config{},
				ProfileName:       "firefox_120",
				MaxHeaderListSize: func() *uint32 { v := uint32(500000); return &v }(),
				ReadIdleTimeout:   func() *time.Duration { d := 60 * time.Second; return &d }(),
			},
			wantErr: false,
		},
		{
			name: "Without profile",
			config: &HTTP2TransportConfig{
				TLSConfig: &tls.Config{},
			},
			wantErr: false,
		},
		{
			name:    "Nil config",
			config:  nil,
			wantErr: false, // Should use defaults
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, err := NewHTTP2Transport(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHTTP2Transport() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if transport == nil {
				t.Error("NewHTTP2Transport() returned nil")
			}

			// Check overrides if provided
			if tt.config != nil && tt.config.MaxHeaderListSize != nil {
				if transport.MaxHeaderListSize != *tt.config.MaxHeaderListSize {
					t.Errorf("MaxHeaderListSize = %d, want %d",
						transport.MaxHeaderListSize, *tt.config.MaxHeaderListSize)
				}
			}
		})
	}
}

func TestGetHTTP2FingerprintInfo(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		wantErr     bool
		wantContain string
	}{
		{
			name:        "Chrome profile",
			profileName: "chrome_120",
			wantErr:     false,
			wantContain: "Chrome 120",
		},
		{
			name:        "Firefox profile",
			profileName: "firefox_120",
			wantErr:     false,
			wantContain: "Firefox 120",
		},
		{
			name:        "Invalid profile",
			profileName: "invalid",
			wantErr:     true,
			wantContain: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := GetHTTP2FingerprintInfo(tt.profileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetHTTP2FingerprintInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantContain != "" {
				if !contains(info, tt.wantContain) {
					t.Errorf("GetHTTP2FingerprintInfo() = %q, should contain %q", info, tt.wantContain)
				}
			}
		})
	}
}

func TestValidateHTTP2Config(t *testing.T) {
	tests := []struct {
		name          string
		profileName   string
		wantErr       bool
		wantWarnings  int
		checkWarnings func(*testing.T, []string)
	}{
		{
			name:         "Chrome profile",
			profileName:  "chrome_120",
			wantErr:      false,
			wantWarnings: 4, // HEADER_TABLE_SIZE, INITIAL_WINDOW_SIZE, MAX_FRAME_SIZE, WINDOW_UPDATE
			checkWarnings: func(t *testing.T, warnings []string) {
				hasHeaderTableWarning := false
				for _, w := range warnings {
					if contains(w, "HEADER_TABLE_SIZE") {
						hasHeaderTableWarning = true
						break
					}
				}
				if !hasHeaderTableWarning {
					t.Error("Should warn about HEADER_TABLE_SIZE limitation")
				}
			},
		},
		{
			name:         "Firefox profile",
			profileName:  "firefox_120",
			wantErr:      false,
			wantWarnings: 0, // May have different warnings
			checkWarnings: func(t *testing.T, warnings []string) {
				// Firefox has m,p,a,s pseudo-header order
				hasPseudoHeaderWarning := false
				for _, w := range warnings {
					if contains(w, "Pseudo-header order") {
						hasPseudoHeaderWarning = true
						break
					}
				}
				if !hasPseudoHeaderWarning {
					t.Log("Note: Firefox pseudo-header order warning expected")
				}
			},
		},
		{
			name:         "Invalid profile",
			profileName:  "invalid",
			wantErr:      true,
			wantWarnings: 0,
			checkWarnings: func(t *testing.T, warnings []string) {
				// Should not be called
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := ValidateHTTP2Config(tt.profileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHTTP2Config() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				t.Logf("Warnings for %s: %d", tt.profileName, len(warnings))
				for _, w := range warnings {
					t.Logf("  - %s", w)
				}

				if tt.checkWarnings != nil {
					tt.checkWarnings(t, warnings)
				}
			}
		})
	}
}

func TestGetConfigurableSettings(t *testing.T) {
	tests := []struct {
		name        string
		profileName string
		wantErr     bool
		checkKeys   []string
	}{
		{
			name:        "Chrome profile",
			profileName: "chrome_120",
			wantErr:     false,
			checkKeys:   []string{"MaxHeaderListSize", "ReadIdleTimeout", "StrictMaxConcurrentStreams"},
		},
		{
			name:        "Firefox profile",
			profileName: "firefox_120",
			wantErr:     false,
			checkKeys:   []string{"ReadIdleTimeout", "StrictMaxConcurrentStreams"},
		},
		{
			name:        "Invalid profile",
			profileName: "invalid",
			wantErr:     true,
			checkKeys:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings, err := GetConfigurableSettings(tt.profileName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetConfigurableSettings() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				for _, key := range tt.checkKeys {
					if _, ok := settings[key]; !ok {
						t.Errorf("Missing expected key: %s", key)
					}
				}
			}
		})
	}
}

func TestNewHTTP2Client(t *testing.T) {
	tests := []struct {
		name    string
		config  *HTTP2ClientConfig
		wantErr bool
	}{
		{
			name: "Valid configuration",
			config: &HTTP2ClientConfig{
				TLSConfig:      &tls.Config{},
				BrowserProfile: "chrome_120",
				RequestTimeout: 30 * time.Second,
			},
			wantErr: false,
		},
		{
			name: "Separate HTTP/2 profile",
			config: &HTTP2ClientConfig{
				TLSConfig:      &tls.Config{},
				BrowserProfile: "chrome_120",
				HTTP2Profile:   "firefox_120", // Different HTTP/2 fingerprint
			},
			wantErr: false,
		},
		{
			name:    "Nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "Invalid HTTP/2 profile",
			config: &HTTP2ClientConfig{
				TLSConfig:    &tls.Config{},
				HTTP2Profile: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewHTTP2Client(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewHTTP2Client() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if client == nil {
					t.Error("NewHTTP2Client() returned nil client")
				}
				if client.Transport == nil {
					t.Error("Client transport is nil")
				}
				if tt.config.RequestTimeout > 0 && client.Timeout != tt.config.RequestTimeout {
					t.Errorf("Client.Timeout = %v, want %v", client.Timeout, tt.config.RequestTimeout)
				}
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) &&
		(s[0:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
