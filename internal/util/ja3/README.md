# JA3/JA4 Fingerprint Spoofing Implementation

## Overview

This implementation adds dynamic JA3/JA4 TLS fingerprint substitution for outgoing TLS connections in GOST's MITM handlers. It allows users to customize the TLS Client Hello to mimic different browsers and evade fingerprint-based blocking.

## Features

- **JA3 String Support**: Parse and apply JA3 fingerprint strings directly in configuration
- **JSON ClientHello Spec**: Load full ClientHello specifications from JSON files (e.g., from tls.peet.ws)
- **Browser Profiles**: Use pre-configured browser profiles (Chrome, Firefox, Safari, Edge, iOS, Android)
- **Handler Support**: Works with HTTP, SOCKS5, and Forward handlers that support MITM
- **Production Ready**: Full integration with existing GOST infrastructure

## Architecture

### Components

1. **JA3 Parser** (`internal/util/ja3/parser.go`)
   - Parses JA3 fingerprint strings (SSLVersion,Ciphers,Extensions,Curves,PointFormats)
   - Loads ClientHello specifications from JSON files
   - Converts cipher names, signature algorithms, and TLS versions

2. **uTLS Spec Builder** (`internal/util/ja3/spec.go`)
   - Builds `utls.ClientHelloSpec` from parsed JA3 data
   - Builds `utls.ClientHelloSpec` from JSON file data
   - Supports custom extension ordering and configuration

3. **Custom TLS Dialer** (`internal/util/ja3/dialer.go`)
   - `DialTLSWithFingerprint`: Establishes TLS connections with custom fingerprints
   - `UpgradeConnWithFingerprint`: Upgrades existing TCP connections to TLS with custom fingerprints
   - Supports JA3 strings, JSON specs, and browser profiles

4. **Handler Integration**
   - Modified `Sniffer` structs in `forwarder` and `sniffing` packages
   - Added JA3/JA4 fields to metadata structures
   - Updated `terminateTLS` functions to use custom dialer when configured

## Configuration

### Metadata Fields

All MITM-capable handlers (http, socks5, forward, etc.) support these metadata fields:

- `mitm.ja3`: JA3 fingerprint string
- `mitm.ja4`: JA4 fingerprint string (informational/logging only)
- `mitm.clientHelloSpecFile`: Path to ClientHello JSON specification file
- `mitm.browserProfile`: Browser profile name (chrome, firefox, safari, edge, ios, android)

**Priority**: `clientHelloSpecFile` > `ja3` > `browserProfile` > default (Chrome Auto)

### Example Configurations

#### Using JA3 String

```yaml
services:
  - name: http-proxy
    addr: :8080
    handler:
      type: http
      metadata:
        sniffing: true
        mitm.certFile: /path/to/ca-cert.pem
        mitm.keyFile: /path/to/ca-key.pem
        mitm.ja3: "771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23,0"
    listener:
      type: tcp
```

#### Using JSON ClientHello Spec

```yaml
services:
  - name: http-proxy
    addr: :8080
    handler:
      type: http
      metadata:
        sniffing: true
        mitm.certFile: /path/to/ca-cert.pem
        mitm.keyFile: /path/to/ca-key.pem
        mitm.clientHelloSpecFile: /path/to/clienthello.json
    listener:
      type: tcp
```

#### Using Browser Profile

```yaml
services:
  - name: http-proxy
    addr: :8080
    handler:
      type: http
      metadata:
        sniffing: true
        mitm.certFile: /path/to/ca-cert.pem
        mitm.keyFile: /path/to/ca-key.pem
        mitm.browserProfile: firefox
    listener:
      type: tcp
```

## Usage Guide

### 1. Generate MITM CA Certificate

```bash
# Generate private key
openssl genrsa -out ca-key.pem 2048

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 \
  -subj "/CN=GOST MITM CA"
```

### 2. Get JA3 Fingerprint

Visit https://tls.peet.ws/api/all with your target browser and copy the `ja3` value:

```json
{
  "tls": {
    "ja3": "771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23,0",
    "ja3_hash": "87a6e6799ead1f216ceb3988e4b7a0dd"
  }
}
```

### 3. Get ClientHello JSON (Optional)

For more precise control, save the entire JSON response from tls.peet.ws:

```bash
curl -s https://tls.peet.ws/api/all > clienthello.json
```

### 4. Configure GOST

Use one of the example configurations above in your `config.yml`.

### 5. Run GOST

```bash
gost -C config.yml
```

## JA3 Format

JA3 fingerprint format: `SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats`

Example: `771,4865-4866-4867,0-23-65281,29-23,0`

- **SSLVersion**: TLS version (771 = TLS 1.2, 772 = TLS 1.3)
- **Ciphers**: Cipher suites separated by `-`
- **Extensions**: TLS extensions separated by `-`
- **EllipticCurves**: Supported curves separated by `-`
- **EllipticCurvePointFormats**: Point formats separated by `-`

## ClientHello JSON Format

The JSON file should match the structure returned by tls.peet.ws:

```json
{
  "tls": {
    "ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
    "extensions": [
      {"name": "server_name (0)", "server_name": "example.com"},
      {"name": "supported_groups (10)", "supported_groups": ["X25519 (29)", "P-256 (23)"]}
    ],
    "ja3": "771,4865-4866,0-10,29-23,0"
  }
}
```

## Browser Profiles

Built-in profiles using uTLS:

- `chrome` / `chrome_auto`: Latest Chrome
- `firefox` / `firefox_auto`: Latest Firefox
- `safari` / `safari_auto`: Latest Safari
- `edge` / `edge_auto`: Latest Edge
- `ios` / `ios_auto`: Latest iOS Safari
- `android`: Android Chrome/WebView

## Supported Handlers

The following handlers support JA3/JA4 fingerprint spoofing:

- `http`: HTTP/HTTPS proxy
- `socks5` / `socks`: SOCKS5 proxy
- `forward`: Port forwarding
- `tcp`: TCP forwarding
- `relay`: Relay protocol
- `ss`: Shadowsocks
- `sni`: SNI proxy
- `sshd`: SSH server with HTTP/SOCKS
- All handlers that support MITM via `sniffing: true`

## Testing

### Verify Your Fingerprint

1. Configure GOST with custom JA3
2. Set your browser to use GOST as proxy
3. Visit https://tls.peet.ws/api/all
4. Check if the `ja3` and `ja3_hash` match your configuration

### Debug Mode

Enable debug logging to see fingerprint application:

```yaml
log:
  level: debug
```

Look for log messages like:
```
[DEBUG] using custom TLS fingerprint for upstream connection to example.com
```

## Implementation Details

### Flow

1. Client connects to GOST handler
2. Handler performs TLS handshake with client (MITM)
3. Handler extracts SNI and other ClientHello info
4. **New**: If JA3/profile configured, build custom ClientHello using uTLS
5. Handler connects to upstream server with custom fingerprint
6. Handler proxies traffic between client and server

### Key Functions

- `ja3.ParseJA3(ja3string)`: Parse JA3 string to structured data
- `ja3.LoadClientHelloSpecFromFile(filename)`: Load JSON spec
- `ja3.BuildClientHelloSpecFromJA3(data, serverName)`: Build uTLS spec from JA3
- `ja3.BuildClientHelloSpecFromFile(spec, serverName)`: Build uTLS spec from JSON
- `ja3.UpgradeConnWithFingerprint(ctx, conn, config)`: Upgrade connection with custom fingerprint

## Dependencies

- **refraction-networking/utls** v1.8.1+: Fork of Go's TLS library with low-level ClientHello control

## Limitations

- JA4 field is informational only (actual fingerprint controlled by JA3/JSON/profile)
- Some advanced TLS features may not be fully supported
- Fingerprint must match TLS version constraints

## Troubleshooting

### TLS Handshake Fails

- Check that JA3 string is valid format
- Verify cipher suites are compatible with target server
- Try using a browser profile instead

### Fingerprint Not Applied

- Ensure `sniffing: true` is set in handler metadata
- Verify MITM certificate/key are configured correctly
- Check logs for errors

### Certificate Errors

- Install MITM CA certificate in client's trust store
- Verify CA certificate can sign server certificates

## References

- [JA3 Specification](https://github.com/salesforce/ja3)
- [uTLS Library](https://github.com/refraction-networking/utls)
- [TLS Fingerprint Service](https://tls.peet.ws)
- [GOST Documentation](https://gost.run)

## License

This implementation follows the same license as GOST (MIT License).
