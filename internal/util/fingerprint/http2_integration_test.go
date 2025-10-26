//go:build integration
// +build integration

package fingerprint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// Integration tests for HTTP/2 fingerprinting against real servers
// Run with: go test -v -tags=integration ./internal/util/fingerprint/

const (
	// Test servers
	testServerHTTP2      = "https://http2.golang.org/"
	testServerHTTP2Pro   = "https://http2.pro/check"
	testServerCloudflare = "https://cloudflare.com"
	testServerGoogle     = "https://www.google.com"
)

func TestHTTP2RealServers_Chrome(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile := "chrome_120"
	testHTTP2Profile(t, profile, []string{
		testServerHTTP2,
		testServerCloudflare,
		testServerGoogle,
	})
}

func TestHTTP2RealServers_Firefox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile := "firefox_120"
	testHTTP2Profile(t, profile, []string{
		testServerHTTP2,
		testServerCloudflare,
	})
}

func TestHTTP2RealServers_Safari(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile := "safari_17"
	testHTTP2Profile(t, profile, []string{
		testServerHTTP2,
		testServerCloudflare,
	})
}

func testHTTP2Profile(t *testing.T, profile string, urls []string) {
	// Get HTTP/2 transport
	transport, err := GetHTTP2Transport(&tls.Config{}, profile)
	if err != nil {
		t.Fatalf("Failed to create HTTP/2 transport: %v", err)
	}

	// Create client
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Log profile info
	info, _ := GetHTTP2FingerprintInfo(profile)
	t.Logf("Testing profile: %s", info)

	// Test each URL
	for _, url := range urls {
		t.Run(url, func(t *testing.T) {
			testHTTP2Request(t, client, url, profile)
		})
	}
}

func testHTTP2Request(t *testing.T, client *http.Client, url, profile string) {
	start := time.Now()

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	duration := time.Since(start)

	// Verify HTTP/2
	if resp.ProtoMajor != 2 {
		t.Errorf("Expected HTTP/2, got HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Log results
	t.Logf("✅ Status: %d, Proto: HTTP/%d.%d, Size: %d bytes, Duration: %v",
		resp.StatusCode, resp.ProtoMajor, resp.ProtoMinor, len(body), duration)

	// Verify successful response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Unexpected status code: %d", resp.StatusCode)
	}

	// Log some headers
	t.Logf("   Server: %s", resp.Header.Get("Server"))
	t.Logf("   Content-Type: %s", resp.Header.Get("Content-Type"))
}

func TestHTTP2ProfileComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profiles := []string{"chrome_120", "firefox_120", "safari_17", "edge_120"}
	url := testServerHTTP2

	results := make(map[string]struct {
		statusCode int
		duration   time.Duration
		bodySize   int
		proto      string
	})

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			transport, err := GetHTTP2Transport(&tls.Config{}, profile)
			if err != nil {
				t.Fatalf("Failed to create transport: %v", err)
			}

			client := &http.Client{
				Transport: transport,
				Timeout:   30 * time.Second,
			}

			start := time.Now()
			resp, err := client.Get(url)
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			results[profile] = struct {
				statusCode int
				duration   time.Duration
				bodySize   int
				proto      string
			}{
				statusCode: resp.StatusCode,
				duration:   duration,
				bodySize:   len(body),
				proto:      fmt.Sprintf("HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor),
			}

			t.Logf("Profile: %s | Status: %d | Proto: %s | Size: %d | Time: %v",
				profile, resp.StatusCode, results[profile].proto, len(body), duration)
		})
	}

	// Compare results
	t.Log("\n=== Profile Comparison ===")
	for profile, result := range results {
		t.Logf("%15s: %s in %v", profile, result.proto, result.duration)
	}
}

func TestHTTP2Fingerprint_CloudflareBotDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test if different profiles bypass bot detection differently
	profiles := []string{"chrome_120", "firefox_120", "curl"}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			transport, err := GetHTTP2Transport(&tls.Config{}, profile)
			if err != nil {
				t.Skipf("Profile %s not available: %v", profile, err)
				return
			}

			client := &http.Client{
				Transport: transport,
				Timeout:   30 * time.Second,
			}

			// Add realistic headers
			req, _ := http.NewRequest("GET", testServerCloudflare, nil)
			req.Header.Set("User-Agent", getBrowserUA(profile))
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
			req.Header.Set("Accept-Language", "en-US,en;q=0.5")
			req.Header.Set("Accept-Encoding", "gzip, deflate, br")
			req.Header.Set("Connection", "keep-alive")
			req.Header.Set("Upgrade-Insecure-Requests", "1")

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("Request failed: %v", err)
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(resp.Body)

			t.Logf("Profile: %s | Status: %d | Proto: HTTP/%d.%d",
				profile, resp.StatusCode, resp.ProtoMajor, resp.ProtoMinor)

			// Check for bot detection (403, 429, challenge page, etc.)
			if resp.StatusCode == http.StatusForbidden {
				t.Logf("⚠️  Bot detection: Status 403 (Forbidden)")
			} else if resp.StatusCode == http.StatusTooManyRequests {
				t.Logf("⚠️  Rate limited: Status 429")
			} else if resp.StatusCode == http.StatusOK {
				// Check for challenge page
				if len(body) > 0 && (contains(string(body), "challenge") || contains(string(body), "captcha")) {
					t.Logf("⚠️  Challenge page detected")
				} else {
					t.Logf("✅ Normal response (likely bypassed detection)")
				}
			}
		})
	}
}

func TestHTTP2ConfigurationValidation(t *testing.T) {
	profiles := []string{"chrome_120", "firefox_120", "safari_17", "edge_120"}

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			// Validate configuration
			warnings, err := ValidateHTTP2Config(profile)
			if err != nil {
				t.Fatalf("Validation failed: %v", err)
			}

			t.Logf("Profile: %s | Warnings: %d", profile, len(warnings))
			for i, warning := range warnings {
				t.Logf("  [%d] %s", i+1, warning)
			}

			// Get configurable settings
			settings, err := GetConfigurableSettings(profile)
			if err != nil {
				t.Fatalf("Failed to get settings: %v", err)
			}

			t.Logf("Configurable settings:")
			for key, value := range settings {
				t.Logf("  - %s: %v", key, value)
			}
		})
	}
}

func TestHTTP2PerformanceBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	profiles := []string{"chrome_120", "firefox_120", "safari_17"}
	iterations := 10
	url := testServerHTTP2

	for _, profile := range profiles {
		t.Run(profile, func(t *testing.T) {
			transport, err := GetHTTP2Transport(&tls.Config{}, profile)
			if err != nil {
				t.Fatalf("Failed to create transport: %v", err)
			}

			client := &http.Client{
				Transport: transport,
				Timeout:   30 * time.Second,
			}

			var totalDuration time.Duration
			var successCount int

			for i := 0; i < iterations; i++ {
				start := time.Now()
				resp, err := client.Get(url)
				duration := time.Since(start)

				if err != nil {
					t.Logf("  Request %d failed: %v", i+1, err)
					continue
				}

				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()

				totalDuration += duration
				successCount++
			}

			if successCount > 0 {
				avgDuration := totalDuration / time.Duration(successCount)
				t.Logf("Profile: %s | Success: %d/%d | Avg: %v",
					profile, successCount, iterations, avgDuration)
			} else {
				t.Errorf("All requests failed for profile %s", profile)
			}
		})
	}
}

func TestHTTP2WithCustomHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	profile := "chrome_120"
	transport, err := GetHTTP2Transport(&tls.Config{}, profile)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Create request with custom headers
	req, _ := http.NewRequest("GET", testServerHTTP2, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.ProtoMajor != 2 {
		t.Errorf("Expected HTTP/2, got HTTP/%d.%d", resp.ProtoMajor, resp.ProtoMinor)
	}

	body, _ := io.ReadAll(resp.Body)
	t.Logf("✅ Request successful: %d bytes, HTTP/%d.%d",
		len(body), resp.ProtoMajor, resp.ProtoMinor)
}

// Helper function to get User-Agent for profile (internal version)
func getBrowserUA(profile string) string {
	userAgents := map[string]string{
		"chrome_120":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"firefox_120": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		"safari_17":   "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		"edge_120":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"curl":        "curl/8.1.2",
	}

	if ua, ok := userAgents[profile]; ok {
		return ua
	}
	return "Mozilla/5.0"
}
