package fingerprint

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// ConfigureHTTP2Transport applies HTTP/2 profile settings to transport
// Note: Due to golang.org/x/net/http2 limitations, not all settings can be applied.
// See HTTP2_LIMITATIONS.md for details.
func ConfigureHTTP2Transport(transport *http2.Transport, profileName string) error {
	profile, ok := GetHTTP2Profile(profileName)
	if !ok {
		return fmt.Errorf("HTTP/2 profile not found: %s", profileName)
	}

	// Apply configurable settings

	// 1. MaxHeaderListSize (SETTINGS_MAX_HEADER_LIST_SIZE = 6)
	// This is the only SETTINGS parameter we can configure
	if maxHeaderSize, ok := profile.Settings[SettingsMaxHeaderListSize]; ok {
		transport.MaxHeaderListSize = maxHeaderSize
	}

	// 2. StrictMaxConcurrentStreams (affects SETTINGS_MAX_CONCURRENT_STREAMS = 3)
	// Enable strict mode if profile specifies max concurrent streams
	if maxStreams, ok := profile.Settings[SettingsMaxConcurrentStreams]; ok {
		transport.StrictMaxConcurrentStreams = maxStreams > 0
	}

	// 3. ReadIdleTimeout - affects connection keepalive behavior
	// Larger WINDOW_UPDATE suggests longer-lived connections
	if profile.WindowUpdate > 10000000 { // >10MB suggests long-lived connection
		transport.ReadIdleTimeout = 30 * time.Second
	} else if profile.WindowUpdate > 1000000 { // >1MB
		transport.ReadIdleTimeout = 15 * time.Second
	} else {
		transport.ReadIdleTimeout = 10 * time.Second
	}

	// 4. AllowHTTP - always false for secure connections
	transport.AllowHTTP = false

	// Limitations (cannot be configured via http2.Transport API):
	// - SETTINGS_HEADER_TABLE_SIZE (1): Hardcoded in http2 library
	// - SETTINGS_ENABLE_PUSH (2): Always 0 (HTTP/2 push deprecated)
	// - SETTINGS_INITIAL_WINDOW_SIZE (4): Not directly configurable
	// - SETTINGS_MAX_FRAME_SIZE (5): Hardcoded to 16384
	// - Initial WINDOW_UPDATE value: Not configurable
	// - Pseudo-header ordering: Controlled internally by http2 library
	// - PRIORITY frame: Not sent by Go http2 client

	return nil
}

// GetHTTP2Transport creates a pre-configured HTTP/2 transport for the specified profile
func GetHTTP2Transport(tlsConfig *tls.Config, profileName string) (*http2.Transport, error) {
	transport := &http2.Transport{
		TLSClientConfig: tlsConfig,
	}

	if err := ConfigureHTTP2Transport(transport, profileName); err != nil {
		return nil, err
	}

	return transport, nil
}

// HTTP2TransportConfig holds configuration for creating HTTP/2 transports
type HTTP2TransportConfig struct {
	TLSConfig   *tls.Config
	ProfileName string

	// Optional overrides
	MaxHeaderListSize *uint32
	ReadIdleTimeout   *time.Duration
	PingTimeout       *time.Duration

	// Advanced options
	DisableCompression bool
	AllowHTTP          bool
}

// NewHTTP2Transport creates a configured HTTP/2 transport with advanced options
func NewHTTP2Transport(config *HTTP2TransportConfig) (*http2.Transport, error) {
	if config == nil {
		config = &HTTP2TransportConfig{}
	}

	transport := &http2.Transport{
		TLSClientConfig:    config.TLSConfig,
		DisableCompression: config.DisableCompression,
		AllowHTTP:          config.AllowHTTP,
	}

	// Apply profile if specified
	if config.ProfileName != "" {
		if err := ConfigureHTTP2Transport(transport, config.ProfileName); err != nil {
			return nil, err
		}
	}

	// Apply overrides
	if config.MaxHeaderListSize != nil {
		transport.MaxHeaderListSize = *config.MaxHeaderListSize
	}
	if config.ReadIdleTimeout != nil {
		transport.ReadIdleTimeout = *config.ReadIdleTimeout
	}
	if config.PingTimeout != nil {
		transport.PingTimeout = *config.PingTimeout
	}

	return transport, nil
}

// GetHTTP2FingerprintInfo returns fingerprint information for logging/debugging
func GetHTTP2FingerprintInfo(profileName string) (string, error) {
	profile, ok := GetHTTP2Profile(profileName)
	if !ok {
		return "", fmt.Errorf("HTTP/2 profile not found: %s", profileName)
	}

	return fmt.Sprintf("Profile: %s | Fingerprint: %s | Configurable: MaxHeaderListSize=%d",
		profile.Name,
		profile.Fingerprint,
		profile.Settings[SettingsMaxHeaderListSize],
	), nil
}

// HTTP2ClientConfig represents a complete HTTP client configuration with HTTP/2 fingerprinting
type HTTP2ClientConfig struct {
	// TLS configuration (includes JA3/JA4)
	TLSConfig *tls.Config

	// Browser profile name (used for both HTTP/2 and TLS)
	BrowserProfile string

	// HTTP/2 specific
	HTTP2Profile string // If different from BrowserProfile

	// Timeouts
	DialTimeout     time.Duration
	RequestTimeout  time.Duration
	ReadIdleTimeout time.Duration

	// Headers
	UserAgent string
	Headers   map[string]string
}

// NewHTTP2Client creates a fully configured HTTP client with HTTP/2 fingerprinting
func NewHTTP2Client(config *HTTP2ClientConfig) (*http.Client, error) {
	if config == nil {
		return nil, fmt.Errorf("HTTP2ClientConfig is nil")
	}

	// Determine HTTP/2 profile
	http2ProfileName := config.HTTP2Profile
	if http2ProfileName == "" {
		http2ProfileName = config.BrowserProfile
	}

	// Create HTTP/2 transport
	http2Transport, err := GetHTTP2Transport(config.TLSConfig, http2ProfileName)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP/2 transport: %w", err)
	}

	// Set timeouts
	if config.ReadIdleTimeout > 0 {
		http2Transport.ReadIdleTimeout = config.ReadIdleTimeout
	}

	// Create HTTP client
	client := &http.Client{
		Transport: http2Transport,
	}

	if config.RequestTimeout > 0 {
		client.Timeout = config.RequestTimeout
	}

	return client, nil
}

// ValidateHTTP2Config validates HTTP/2 configuration and returns warnings about limitations
func ValidateHTTP2Config(profileName string) (warnings []string, err error) {
	profile, ok := GetHTTP2Profile(profileName)
	if !ok {
		return nil, fmt.Errorf("HTTP/2 profile not found: %s", profileName)
	}

	warnings = make([]string, 0)

	// Check for non-configurable settings
	if _, ok := profile.Settings[SettingsHeaderTableSize]; ok {
		warnings = append(warnings, "SETTINGS_HEADER_TABLE_SIZE cannot be configured (http2 library limitation)")
	}

	if enablePush, ok := profile.Settings[SettingsEnablePush]; ok && enablePush != 0 {
		warnings = append(warnings, "SETTINGS_ENABLE_PUSH is always 0 in Go (HTTP/2 push deprecated)")
	}

	if _, ok := profile.Settings[SettingsInitialWindowSize]; ok {
		warnings = append(warnings, "SETTINGS_INITIAL_WINDOW_SIZE cannot be configured directly")
	}

	if _, ok := profile.Settings[SettingsMaxFrameSize]; ok {
		warnings = append(warnings, "SETTINGS_MAX_FRAME_SIZE is hardcoded to 16384")
	}

	if profile.WindowUpdate != 0 && profile.WindowUpdate != 65535 {
		warnings = append(warnings, fmt.Sprintf("Initial WINDOW_UPDATE (%d) cannot be configured", profile.WindowUpdate))
	}

	if profile.PseudoHeaderOrder != "" && profile.PseudoHeaderOrder != "m,a,s,p" {
		warnings = append(warnings, fmt.Sprintf("Pseudo-header order '%s' cannot be configured (library uses 'm,a,s,p')", profile.PseudoHeaderOrder))
	}

	if profile.Priority != nil {
		warnings = append(warnings, "PRIORITY frames are not sent by Go HTTP/2 client")
	}

	return warnings, nil
}

// GetConfigurableSettings returns which settings can actually be configured
func GetConfigurableSettings(profileName string) (map[string]interface{}, error) {
	profile, ok := GetHTTP2Profile(profileName)
	if !ok {
		return nil, fmt.Errorf("HTTP/2 profile not found: %s", profileName)
	}

	configurable := make(map[string]interface{})

	// Only MaxHeaderListSize is truly configurable
	if maxHeaderSize, ok := profile.Settings[SettingsMaxHeaderListSize]; ok {
		configurable["MaxHeaderListSize"] = maxHeaderSize
	}

	// Indirectly configurable via timeouts
	configurable["ReadIdleTimeout"] = "inferred from WindowUpdate size"
	configurable["StrictMaxConcurrentStreams"] = profile.Settings[SettingsMaxConcurrentStreams] > 0

	return configurable, nil
}
