package ja3

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// TLSDialerConfig holds configuration for custom TLS dialing
type TLSDialerConfig struct {
	// JA3 fingerprint string
	JA3 string

	// Path to ClientHello spec JSON file
	ClientHelloSpecFile string

	// Browser profile (chrome, firefox, safari, etc.) for auto mode
	BrowserProfile string

	// Server name for SNI
	ServerName string

	// ALPN protocols
	ALPNProtocols []string

	// Standard TLS config (for InsecureSkipVerify, RootCAs, etc.)
	TLSConfig *tls.Config
}

// DialTLSWithFingerprint establishes a TLS connection with custom fingerprint
func DialTLSWithFingerprint(ctx context.Context, network, addr string, config *TLSDialerConfig) (net.Conn, error) {
	if config == nil {
		return nil, fmt.Errorf("TLSDialerConfig is nil")
	}

	// Establish TCP connection
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Build utls config
	utlsConfig := &utls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.TLSConfig != nil && config.TLSConfig.InsecureSkipVerify,
		NextProtos:         config.ALPNProtocols,
	}

	if config.TLSConfig != nil {
		utlsConfig.RootCAs = config.TLSConfig.RootCAs
		utlsConfig.MinVersion = config.TLSConfig.MinVersion
		utlsConfig.MaxVersion = config.TLSConfig.MaxVersion
	}

	var clientHelloID utls.ClientHelloID
	var customSpec *utls.ClientHelloSpec

	// Determine how to build ClientHello
	if config.ClientHelloSpecFile != "" {
		// Try parsing as tls.peet.ws JSON format first
		customSpec, err = ParseClientHelloJSON(config.ClientHelloSpecFile)
		if err != nil {
			// Fallback to old custom JSON format
			specFile, err2 := LoadClientHelloSpecFromFile(config.ClientHelloSpecFile)
			if err2 != nil {
				rawConn.Close()
				return nil, fmt.Errorf("failed to load ClientHello spec (tried both formats): peet.ws format: %w, custom format: %v", err, err2)
			}
			customSpec, err = BuildClientHelloSpecFromFile(specFile, config.ServerName)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("failed to build ClientHello spec from file: %w", err)
			}
		}
		clientHelloID = utls.HelloCustom

	} else if config.JA3 != "" {
		// Parse JA3 string
		ja3Data, err := ParseJA3(config.JA3)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to parse JA3: %w", err)
		}
		customSpec, err = BuildClientHelloSpecFromJA3(ja3Data, config.ServerName)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to build ClientHello spec from JA3: %w", err)
		}
		clientHelloID = utls.HelloCustom

	} else if config.BrowserProfile != "" {
		// Try to get JA3 from predefined browser profile
		if ja3String := GetBrowserJA3(config.BrowserProfile); ja3String != "" {
			ja3Data, err := ParseJA3(ja3String)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("failed to parse JA3 from profile %s: %w", config.BrowserProfile, err)
			}
			customSpec, err = BuildClientHelloSpecFromJA3(ja3Data, config.ServerName)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("failed to build ClientHello spec from profile %s: %w", config.BrowserProfile, err)
			}
			clientHelloID = utls.HelloCustom
		} else {
			// Fallback to uTLS built-in profiles
			clientHelloID = GetUTLSClientHelloID(config.BrowserProfile)
		}

	} else {
		// Default to Chrome Auto
		clientHelloID = utls.HelloChrome_Auto
	}

	// Create uTLS connection
	uconn := utls.UClient(rawConn, utlsConfig, clientHelloID)

	// Apply custom spec if provided
	if customSpec != nil {
		if err := uconn.ApplyPreset(customSpec); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to apply custom ClientHello spec: %w", err)
		}
	}

	// Perform TLS handshake
	if err := uconn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return uconn, nil
}

// DialTLSWithJA3 is a convenience function for dialing with JA3 string
func DialTLSWithJA3(ctx context.Context, network, addr, ja3, serverName string, tlsConfig *tls.Config) (net.Conn, error) {
	config := &TLSDialerConfig{
		JA3:        ja3,
		ServerName: serverName,
		TLSConfig:  tlsConfig,
	}
	return DialTLSWithFingerprint(ctx, network, addr, config)
}

// DialTLSWithProfile is a convenience function for dialing with browser profile
func DialTLSWithProfile(ctx context.Context, network, addr, profile, serverName string, tlsConfig *tls.Config) (net.Conn, error) {
	config := &TLSDialerConfig{
		BrowserProfile: profile,
		ServerName:     serverName,
		TLSConfig:      tlsConfig,
	}
	return DialTLSWithFingerprint(ctx, network, addr, config)
}

// UpgradeConnWithFingerprint upgrades an existing net.Conn to TLS with custom fingerprint
// This is useful when you already have a TCP connection and want to upgrade it to TLS
func UpgradeConnWithFingerprint(ctx context.Context, rawConn net.Conn, config *TLSDialerConfig) (net.Conn, error) {
	if config == nil {
		return nil, fmt.Errorf("TLSDialerConfig is nil")
	}

	// Build utls config
	utlsConfig := &utls.Config{
		ServerName:         config.ServerName,
		InsecureSkipVerify: config.TLSConfig != nil && config.TLSConfig.InsecureSkipVerify,
		NextProtos:         config.ALPNProtocols,
	}

	if config.TLSConfig != nil {
		utlsConfig.RootCAs = config.TLSConfig.RootCAs
		utlsConfig.MinVersion = config.TLSConfig.MinVersion
		utlsConfig.MaxVersion = config.TLSConfig.MaxVersion
	}

	var clientHelloID utls.ClientHelloID
	var customSpec *utls.ClientHelloSpec
	var err error

	// Determine how to build ClientHello
	if config.ClientHelloSpecFile != "" {
		// Try parsing as tls.peet.ws JSON format first
		customSpec, err = ParseClientHelloJSON(config.ClientHelloSpecFile)
		if err != nil {
			// Fallback to old custom JSON format
			specFile, err2 := LoadClientHelloSpecFromFile(config.ClientHelloSpecFile)
			if err2 != nil {
				return nil, fmt.Errorf("failed to load ClientHello spec (tried both formats): peet.ws format: %w, custom format: %v", err, err2)
			}
			customSpec, err = BuildClientHelloSpecFromFile(specFile, config.ServerName)
			if err != nil {
				return nil, fmt.Errorf("failed to build ClientHello spec from file: %w", err)
			}
		}
		clientHelloID = utls.HelloCustom

	} else if config.JA3 != "" {
		// Parse JA3 string
		ja3Data, err := ParseJA3(config.JA3)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JA3: %w", err)
		}
		customSpec, err = BuildClientHelloSpecFromJA3(ja3Data, config.ServerName)
		if err != nil {
			return nil, fmt.Errorf("failed to build ClientHello spec from JA3: %w", err)
		}
		clientHelloID = utls.HelloCustom

	} else if config.BrowserProfile != "" {
		// Try to get JA3 from predefined browser profile
		if ja3String := GetBrowserJA3(config.BrowserProfile); ja3String != "" {
			ja3Data, err := ParseJA3(ja3String)
			if err != nil {
				return nil, fmt.Errorf("failed to parse JA3 from profile %s: %w", config.BrowserProfile, err)
			}
			customSpec, err = BuildClientHelloSpecFromJA3(ja3Data, config.ServerName)
			if err != nil {
				return nil, fmt.Errorf("failed to build ClientHello spec from profile %s: %w", config.BrowserProfile, err)
			}
			clientHelloID = utls.HelloCustom
		} else {
			// Fallback to uTLS built-in profiles
			clientHelloID = GetUTLSClientHelloID(config.BrowserProfile)
		}

	} else {
		// Default to Chrome Auto
		clientHelloID = utls.HelloChrome_Auto
	}

	// Create uTLS connection
	uconn := utls.UClient(rawConn, utlsConfig, clientHelloID)

	// Apply custom spec if provided
	if customSpec != nil {
		if err := uconn.ApplyPreset(customSpec); err != nil {
			return nil, fmt.Errorf("failed to apply custom ClientHello spec: %w", err)
		}
	}

	// Perform TLS handshake
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return uconn, nil
}
