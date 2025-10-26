package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// HTTP2Fingerprint represents an Akamai HTTP/2 fingerprint
// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|HEADERS_PRIORITY
// Example: 1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p
type HTTP2Fingerprint struct {
	// SETTINGS frame parameters (key:value pairs)
	Settings map[uint16]uint32

	// WINDOW_UPDATE increment value
	WindowUpdate uint32

	// PRIORITY stream dependency and weight
	Priority *HTTP2Priority

	// Header compression table size and priority
	HeaderTableSize   uint32
	PseudoHeaderOrder string // Order of pseudo-headers (e.g., "m,a,s,p" for :method,:authority,:scheme,:path)
}

// HTTP2Priority represents stream priority information
type HTTP2Priority struct {
	StreamDependency uint32
	Weight           uint8
	Exclusive        bool
}

// HTTP2Profile represents a complete HTTP/2 fingerprint profile for a browser
type HTTP2Profile struct {
	Name        string
	Fingerprint string // Akamai format fingerprint

	// Parsed components
	Settings          map[uint16]uint32
	WindowUpdate      uint32
	Priority          *HTTP2Priority
	HeaderTableSize   uint32
	PseudoHeaderOrder string
}

// Common HTTP/2 SETTINGS IDs
const (
	SettingsHeaderTableSize      uint16 = 0x1
	SettingsEnablePush           uint16 = 0x2
	SettingsMaxConcurrentStreams uint16 = 0x3
	SettingsInitialWindowSize    uint16 = 0x4
	SettingsMaxFrameSize         uint16 = 0x5
	SettingsMaxHeaderListSize    uint16 = 0x6
)

// HTTP2ProfilesDB contains HTTP/2 fingerprints for common browsers
var HTTP2ProfilesDB = map[string]HTTP2Profile{
	"chrome_120": {
		Name:              "Chrome 120",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"chrome_108": {
		Name:              "Chrome 108",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"firefox_120": {
		Name:              "Firefox 120",
		Fingerprint:       "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 4: 131072, 5: 16384},
		WindowUpdate:      12517377,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: false},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,p,a,s",
	},
	"firefox_102": {
		Name:              "Firefox 102",
		Fingerprint:       "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 4: 131072, 5: 16384},
		WindowUpdate:      12517377,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: false},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,p,a,s",
	},
	"safari_17": {
		Name:              "Safari 17",
		Fingerprint:       "2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   4096,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"safari_ios_17": {
		Name:              "Safari iOS 17",
		Fingerprint:       "2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   4096,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"edge_120": {
		Name:              "Edge 120",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"android_chrome": {
		Name:              "Chrome Android",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"brave_browser": {
		Name:              "Brave Browser",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"samsung_internet": {
		Name:              "Samsung Internet",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"firefox_android": {
		Name:              "Firefox Android",
		Fingerprint:       "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 4: 131072, 5: 16384},
		WindowUpdate:      12517377,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: false},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,p,a,s",
	},
	"safari_ipad": {
		Name:              "Safari iPad",
		Fingerprint:       "2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   4096,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"opera_gx": {
		Name:              "Opera GX",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"vivaldi": {
		Name:              "Vivaldi",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"tor_browser": {
		Name:              "Tor Browser",
		Fingerprint:       "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 4: 131072, 5: 16384},
		WindowUpdate:      12517377,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: false},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,p,a,s",
	},
	"yandex_browser": {
		Name:              "Yandex Browser",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"uc_browser": {
		Name:              "UC Browser",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"whale_browser": {
		Name:              "Naver Whale",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"edge_mobile": {
		Name:              "Edge Mobile",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"opera_mobile": {
		Name:              "Opera Mobile",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"duckduckgo_browser": {
		Name:              "DuckDuckGo Browser",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"ecosia_browser": {
		Name:              "Ecosia Browser",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"maxthon_browser": {
		Name:              "Maxthon Browser",
		Fingerprint:       "1:65536;2:0;3:100;4:6291456;6:262144|15663105|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 0, 3: 100, 4: 6291456, 6: 262144},
		WindowUpdate:      15663105,
		Priority:          &HTTP2Priority{StreamDependency: 0, Weight: 255, Exclusive: true},
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"curl_latest": {
		Name:              "curl 8.x",
		Fingerprint:       "2:0;3:100;4:1048576|1048576|0|m,a,s,p",
		Settings:          map[uint16]uint32{2: 0, 3: 100, 4: 1048576},
		WindowUpdate:      1048576,
		Priority:          nil,
		HeaderTableSize:   4096,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"go_http": {
		Name:              "Go HTTP Client",
		Fingerprint:       "3:100;4:1048576;6:262144|1048576|0|m,a,s,p",
		Settings:          map[uint16]uint32{3: 100, 4: 1048576, 6: 262144},
		WindowUpdate:      1048576,
		Priority:          nil,
		HeaderTableSize:   4096,
		PseudoHeaderOrder: "m,a,s,p",
	},
	"okhttp_android": {
		Name:              "OkHttp Android",
		Fingerprint:       "1:65536;2:1;3:1000;4:6291456|10485760|0|m,a,s,p",
		Settings:          map[uint16]uint32{1: 65536, 2: 1, 3: 1000, 4: 6291456},
		WindowUpdate:      10485760,
		Priority:          nil,
		HeaderTableSize:   65536,
		PseudoHeaderOrder: "m,a,s,p",
	},
}

// GenerateHTTP2Fingerprint creates an Akamai-format HTTP/2 fingerprint string
func GenerateHTTP2Fingerprint(fp *HTTP2Fingerprint) string {
	// Part 1: SETTINGS (sorted by key)
	var settingsKeys []int
	for k := range fp.Settings {
		settingsKeys = append(settingsKeys, int(k))
	}
	sort.Ints(settingsKeys)

	var settingsParts []string
	for _, k := range settingsKeys {
		settingsParts = append(settingsParts, fmt.Sprintf("%d:%d", k, fp.Settings[uint16(k)]))
	}
	settingsStr := strings.Join(settingsParts, ";")

	// Part 2: WINDOW_UPDATE
	windowUpdateStr := fmt.Sprintf("%d", fp.WindowUpdate)

	// Part 3: PRIORITY
	priorityStr := "0"
	if fp.Priority != nil {
		priorityStr = fmt.Sprintf("%d", fp.Priority.StreamDependency)
	}

	// Part 4: Pseudo-header order
	pseudoHeaderOrder := fp.PseudoHeaderOrder
	if pseudoHeaderOrder == "" {
		pseudoHeaderOrder = "m,a,s,p" // default
	}

	return fmt.Sprintf("%s|%s|%s|%s", settingsStr, windowUpdateStr, priorityStr, pseudoHeaderOrder)
}

// ParseHTTP2Fingerprint parses an Akamai-format HTTP/2 fingerprint
func ParseHTTP2Fingerprint(fingerprint string) (*HTTP2Fingerprint, error) {
	parts := strings.Split(fingerprint, "|")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid HTTP/2 fingerprint format: expected 4 parts, got %d", len(parts))
	}

	fp := &HTTP2Fingerprint{
		Settings: make(map[uint16]uint32),
	}

	// Parse SETTINGS
	if parts[0] != "" {
		settings := strings.Split(parts[0], ";")
		for _, setting := range settings {
			kv := strings.Split(setting, ":")
			if len(kv) != 2 {
				continue
			}
			key, err := strconv.ParseUint(kv[0], 10, 16)
			if err != nil {
				continue
			}
			value, err := strconv.ParseUint(kv[1], 10, 32)
			if err != nil {
				continue
			}
			fp.Settings[uint16(key)] = uint32(value)
		}
	}

	// Parse WINDOW_UPDATE
	if windowUpdate, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
		fp.WindowUpdate = uint32(windowUpdate)
	}

	// Parse PRIORITY (simplified - just stream dependency)
	if streamDep, err := strconv.ParseUint(parts[2], 10, 32); err == nil && streamDep > 0 {
		fp.Priority = &HTTP2Priority{
			StreamDependency: uint32(streamDep),
			Weight:           255,
			Exclusive:        true,
		}
	}

	// Parse pseudo-header order
	fp.PseudoHeaderOrder = parts[3]

	return fp, nil
}

// GetHTTP2Profile returns an HTTP/2 profile by name
func GetHTTP2Profile(name string) (HTTP2Profile, bool) {
	profile, ok := HTTP2ProfilesDB[name]
	return profile, ok
}

// GetHTTP2Fingerprint returns the HTTP/2 fingerprint string for a profile
func GetHTTP2Fingerprint(profileName string) string {
	if profile, ok := HTTP2ProfilesDB[profileName]; ok {
		return profile.Fingerprint
	}
	return ""
}

// GenerateHTTP2FingerprintHash creates a hash of the HTTP/2 fingerprint
func GenerateHTTP2FingerprintHash(fingerprint string) string {
	hash := sha256.Sum256([]byte(fingerprint))
	return hex.EncodeToString(hash[:])
}

// ListHTTP2Profiles returns all available HTTP/2 profile names
func ListHTTP2Profiles() []string {
	profiles := make([]string, 0, len(HTTP2ProfilesDB))
	for name := range HTTP2ProfilesDB {
		profiles = append(profiles, name)
	}
	sort.Strings(profiles)
	return profiles
}
