package ja3

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// BuildClientHelloSpecFromJA3 builds a utls.ClientHelloSpec from parsed JA3 data
func BuildClientHelloSpecFromJA3(data *JA3Data, serverName string) (*utls.ClientHelloSpec, error) {
	if data == nil {
		return nil, fmt.Errorf("JA3 data is nil")
	}

	spec := &utls.ClientHelloSpec{
		TLSVersMin:   data.Version,
		TLSVersMax:   data.Version,
		CipherSuites: make([]uint16, len(data.CipherSuites)),
		Extensions:   make([]utls.TLSExtension, 0),
	}

	// Copy cipher suites
	copy(spec.CipherSuites, data.CipherSuites)

	// Build extensions based on extension IDs
	for _, extID := range data.Extensions {
		ext := buildExtension(extID, data, serverName)
		if ext != nil {
			spec.Extensions = append(spec.Extensions, ext)
		}
	}

	return spec, nil
}

// BuildClientHelloSpecFromFile builds a utls.ClientHelloSpec from JSON file
func BuildClientHelloSpecFromFile(spec *ClientHelloSpecFile, serverName string) (*utls.ClientHelloSpec, error) {
	if spec == nil {
		return nil, fmt.Errorf("ClientHelloSpec file data is nil")
	}

	helloSpec := &utls.ClientHelloSpec{
		CipherSuites: make([]uint16, 0),
		Extensions:   make([]utls.TLSExtension, 0),
	}

	// Parse cipher suites
	for _, cipherName := range spec.TLS.Ciphers {
		cipherID, err := ParseCipherName(cipherName)
		if err != nil {
			// Skip unknown ciphers
			continue
		}
		helloSpec.CipherSuites = append(helloSpec.CipherSuites, cipherID)
	}

	// Parse TLS version
	if spec.TLS.TLSVersionRecord != "" {
		version, err := ParseTLSVersion(spec.TLS.TLSVersionRecord)
		if err == nil {
			helloSpec.TLSVersMin = version
			helloSpec.TLSVersMax = version
		}
	}

	// Parse extensions
	var supportedGroups []uint16
	var supportedPoints []uint8
	var signatureAlgorithms []utls.SignatureScheme
	var supportedVersions []uint16
	var alpnProtocols []string

	for _, ext := range spec.TLS.Extensions {
		switch {
		case strings.Contains(ext.Name, "server_name"):
			if serverName != "" {
				helloSpec.Extensions = append(helloSpec.Extensions, &utls.SNIExtension{
					ServerName: serverName,
				})
			}

		case strings.Contains(ext.Name, "supported_groups"):
			for _, groupName := range ext.SupportedGroups {
				groupID, err := ParseSupportedGroup(groupName)
				if err == nil {
					supportedGroups = append(supportedGroups, groupID)
				}
			}

		case strings.Contains(ext.Name, "ec_point_formats"):
			for _, pointStr := range ext.EllipticCurvesPointFormats {
				// Parse hex format like "0x00"
				pointStr = strings.TrimPrefix(pointStr, "0x")
				if len(pointStr) == 2 {
					var point uint8
					fmt.Sscanf(pointStr, "%02x", &point)
					supportedPoints = append(supportedPoints, point)
				}
			}

		case strings.Contains(ext.Name, "signature_algorithms"):
			for _, sigAlgName := range ext.SignatureAlgorithms {
				sigAlgID, err := ParseSignatureAlgorithm(sigAlgName)
				if err == nil {
					signatureAlgorithms = append(signatureAlgorithms, utls.SignatureScheme(sigAlgID))
				}
			}

		case strings.Contains(ext.Name, "application_layer_protocol_negotiation"):
			alpnProtocols = ext.Protocols

		case strings.Contains(ext.Name, "supported_versions"):
			for _, verStr := range ext.Versions {
				verID, err := ParseTLSVersion(verStr)
				if err == nil {
					supportedVersions = append(supportedVersions, verID)
				}
			}

		case strings.Contains(ext.Name, "key_share"):
			// Key share will be generated automatically by utls

		case strings.Contains(ext.Name, "padding"):
			if ext.PaddingDataLength > 0 {
				helloSpec.Extensions = append(helloSpec.Extensions, &utls.UtlsPaddingExtension{
					GetPaddingLen: utls.BoringPaddingStyle,
				})
			}

		case strings.Contains(ext.Name, "session_ticket"):
			helloSpec.Extensions = append(helloSpec.Extensions, &utls.SessionTicketExtension{})

		case strings.Contains(ext.Name, "extended_master_secret"):
			helloSpec.Extensions = append(helloSpec.Extensions, &utls.ExtendedMasterSecretExtension{})

		case strings.Contains(ext.Name, "status_request"):
			helloSpec.Extensions = append(helloSpec.Extensions, &utls.StatusRequestExtension{})

		case strings.Contains(ext.Name, "psk_key_exchange_modes"):
			helloSpec.Extensions = append(helloSpec.Extensions, &utls.PSKKeyExchangeModesExtension{
				Modes: []uint8{1}, // psk_dhe_ke
			})

		case strings.Contains(ext.Name, "signed_certificate_timestamp"):
			helloSpec.Extensions = append(helloSpec.Extensions, &utls.SCTExtension{})

		case strings.Contains(ext.Name, "renegotiation_info"):
			helloSpec.Extensions = append(helloSpec.Extensions, &utls.RenegotiationInfoExtension{
				Renegotiation: utls.RenegotiateOnceAsClient,
			})
		}
	}

	// Add collected extensions
	if len(supportedGroups) > 0 {
		curves := make([]utls.CurveID, len(supportedGroups))
		for i, g := range supportedGroups {
			curves[i] = utls.CurveID(g)
		}
		helloSpec.Extensions = append(helloSpec.Extensions, &utls.SupportedCurvesExtension{
			Curves: curves,
		})
	}
	if len(supportedPoints) > 0 {
		helloSpec.Extensions = append(helloSpec.Extensions, &utls.SupportedPointsExtension{
			SupportedPoints: supportedPoints,
		})
	}
	if len(signatureAlgorithms) > 0 {
		helloSpec.Extensions = append(helloSpec.Extensions, &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: signatureAlgorithms,
		})
	}
	if len(supportedVersions) > 0 {
		helloSpec.Extensions = append(helloSpec.Extensions, &utls.SupportedVersionsExtension{
			Versions: supportedVersions,
		})
	}
	if len(alpnProtocols) > 0 {
		helloSpec.Extensions = append(helloSpec.Extensions, &utls.ALPNExtension{
			AlpnProtocols: alpnProtocols,
		})
	}

	return helloSpec, nil
}

// buildExtension creates a TLS extension based on extension ID
func buildExtension(extID uint16, data *JA3Data, serverName string) utls.TLSExtension {
	switch extID {
	case 0: // SNI
		if serverName != "" {
			return &utls.SNIExtension{ServerName: serverName}
		}
	case 5: // status_request
		return &utls.StatusRequestExtension{}
	case 10: // supported_groups
		if len(data.SupportedGroups) > 0 {
			curves := make([]utls.CurveID, len(data.SupportedGroups))
			for i, g := range data.SupportedGroups {
				curves[i] = utls.CurveID(g)
			}
			return &utls.SupportedCurvesExtension{Curves: curves}
		}
	case 11: // ec_point_formats
		if len(data.EllipticCurvePoint) > 0 {
			return &utls.SupportedPointsExtension{SupportedPoints: data.EllipticCurvePoint}
		}
	case 13: // signature_algorithms
		return &utls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			},
		}
	case 16: // ALPN
		return &utls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		}
	case 18: // signed_certificate_timestamp
		return &utls.SCTExtension{}
	case 21: // padding
		return &utls.UtlsPaddingExtension{
			GetPaddingLen: utls.BoringPaddingStyle,
		}
	case 23: // extended_master_secret
		return &utls.ExtendedMasterSecretExtension{}
	case 27: // compress_certificate - not supported in all utls versions, use generic extension
		return &utls.GenericExtension{Id: 27}
	case 35: // session_ticket
		return &utls.SessionTicketExtension{}
	case 43: // supported_versions
		return &utls.SupportedVersionsExtension{
			Versions: []uint16{
				utls.VersionTLS13,
				utls.VersionTLS12,
			},
		}
	case 45: // psk_key_exchange_modes
		return &utls.PSKKeyExchangeModesExtension{
			Modes: []uint8{1}, // psk_dhe_ke
		}
	case 51: // key_share
		return &utls.KeyShareExtension{
			KeyShares: []utls.KeyShare{
				{Group: utls.X25519},
			},
		}
	case 65281: // renegotiation_info
		return &utls.RenegotiationInfoExtension{
			Renegotiation: utls.RenegotiateOnceAsClient,
		}
	}
	return &utls.GenericExtension{Id: extID}
}

// GetUTLSClientHelloID returns a utls.ClientHelloID for common browser profiles
func GetUTLSClientHelloID(profile string) utls.ClientHelloID {
	profile = strings.ToLower(profile)
	switch profile {
	case "chrome", "chrome_auto":
		return utls.HelloChrome_Auto
	case "firefox", "firefox_auto":
		return utls.HelloFirefox_Auto
	case "safari", "safari_auto":
		return utls.HelloSafari_Auto
	case "edge", "edge_auto":
		return utls.HelloEdge_Auto
	case "ios", "ios_auto":
		return utls.HelloIOS_Auto
	case "android", "android_auto":
		return utls.HelloAndroid_11_OkHttp
	default:
		return utls.HelloChrome_Auto
	}
}

// GenerateRandomSessionID generates a random session ID
func GenerateRandomSessionID() []byte {
	// Generate 32 bytes random session ID
	randomData := make([]byte, 32)
	hash := sha256.Sum256([]byte(hex.EncodeToString(randomData)))
	return hash[:]
}
