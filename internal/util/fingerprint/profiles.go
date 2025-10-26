package fingerprint

// BrowserProfile represents a predefined browser fingerprint
type BrowserProfile struct {
	Name      string
	JA3       string
	UserAgent string
	// JA4 fingerprint (optional, for HTTP/3)
	JA4 string
}

// Common browser profiles with real-world JA3 fingerprints
var BrowserProfiles = map[string]BrowserProfile{
	"chrome_modern": {
		Name:      "Chrome 120+ (Modern)",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		JA4:       "t13d1715h2_8daaf6152771_02713d6af862",
	},
	"chrome_108": {
		Name:      "Chrome 108",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		JA4:       "t13d1516h2_8daaf6152771_e5627efa2ab1",
	},
	"firefox_latest": {
		Name:      "Firefox 120+",
		JA3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
		JA4:       "t13d1517h2_5b57614c22b0_3d5424432c57",
	},
	"firefox_102": {
		Name:      "Firefox 102 ESR",
		JA3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0",
		JA4:       "t13d1515h2_5b57614c22b0_cd85d2d88918",
	},
	"safari_17": {
		Name:      "Safari 17 (macOS)",
		JA3:       "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
		JA4:       "t13d1714h2_9e7b989ebec8_4e5db9f566cb",
	},
	"safari_ios_17": {
		Name:      "Safari iOS 17",
		JA3:       "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-16-5-13,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		JA4:       "t13d1312h2_9e7b989ebec8_37e0c9b7f7e5",
	},
	"edge_latest": {
		Name:      "Edge 120+ (Chromium)",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		JA4:       "t13d1715h2_8daaf6152771_02713d6af862",
	},
	"android_chrome": {
		Name:      "Chrome Android 120",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		JA4:       "t13d1614h2_8daaf6152771_a7f0724e1fa9",
	},
	"okhttp_android": {
		Name:      "OkHttp Android Client",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		UserAgent: "okhttp/4.11.0",
		JA4:       "t13d1413h2_8daaf6152771_224e4e1f2d0a",
	},
	// Legacy browsers
	"chrome_98": {
		Name:      "Chrome 98 (Legacy)",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
		JA4:       "t13d1615h2_8daaf6152771_b0da82dd1658",
	},
	"firefox_91": {
		Name:      "Firefox 91",
		JA3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
		JA4:       "t13d1514h2_5b57614c22b0_e7c285222651",
	},
	// Bots and crawlers
	"curl_latest": {
		Name:      "curl 8.x",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		UserAgent: "curl/8.1.2",
		JA4:       "t13d1413h2_8daaf6152771_2a623c22973b",
	},
	"python_requests": {
		Name:      "Python Requests",
		JA3:       "771,4866-4867-4865-49200-49196-49192-49188-49172-49162-159-107-57-52393-52392-52394-65413-196-136-129-157-61-53-132-49199-49195-49191-49187-49171-49161-158-103-51-190-69-156-60-47-186-65-49169-49159-5-4-49170-49160-22-10-255,11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2",
		UserAgent: "python-requests/2.31.0",
		JA4:       "t13d3222h2_bca230a689ed_a4ad957c2b9b",
	},
	"go_http": {
		Name:      "Go HTTP Client",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		UserAgent: "Go-http-client/2.0",
		JA4:       "t13d1413h2_8daaf6152771_3b786b34c4ab",
	},
	// Modern browsers
	"brave_browser": {
		Name:      "Brave Browser 1.60+",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		JA4:       "t13d1715h2_8daaf6152771_02713d6af862",
	},
	"samsung_internet": {
		Name:      "Samsung Internet 20",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/20.0 Chrome/106.0.5249.126 Mobile Safari/537.36",
		JA4:       "t13d1614h2_8daaf6152771_e1a4b2c5d3f6",
	},
	"firefox_android": {
		Name:      "Firefox Android 120",
		JA3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (Android 13; Mobile; rv:120.0) Gecko/120.0 Firefox/120.0",
		JA4:       "t13d1515h2_5b57614c22b0_8f7e6d5c4b3a",
	},
	"safari_ipad": {
		Name:      "Safari iPad iOS 17",
		JA3:       "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47,0-23-65281-10-11-16-5-13,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		JA4:       "t13d1312h2_9e7b989ebec8_2a1b3c4d5e6f",
	},
	"opera_gx": {
		Name:      "Opera GX",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
		JA4:       "t13d1715h2_8daaf6152771_f2e3d4c5b6a7",
	},
	"vivaldi": {
		Name:      "Vivaldi Browser",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5",
		JA4:       "t13d1715h2_8daaf6152771_a9b8c7d6e5f4",
	},
	"tor_browser": {
		Name:      "Tor Browser",
		JA3:       "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0",
		JA4:       "t13d1515h2_5b57614c22b0_1f2e3d4c5b6a",
	},
	"yandex_browser": {
		Name:      "Yandex Browser",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 YaBrowser/23.11 Safari/537.36",
		JA4:       "t13d1715h2_8daaf6152771_c1d2e3f4a5b6",
	},
	"uc_browser": {
		Name:      "UC Browser Mobile",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Linux; U; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) UCBrowser/15.5.0.1000 Mobile Safari/537.36",
		JA4:       "t13d1413h2_8daaf6152771_7a8b9c0d1e2f",
	},
	"whale_browser": {
		Name:      "Naver Whale Browser",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Whale/3.24 Safari/537.36",
		JA4:       "t13d1715h2_8daaf6152771_3d4e5f6a7b8c",
	},
	"edge_mobile": {
		Name:      "Edge Mobile Android",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 EdgA/120.0.0.0",
		JA4:       "t13d1614h2_8daaf6152771_9e8f7d6c5b4a",
	},
	"opera_mobile": {
		Name:      "Opera Mobile",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 OPR/76.2",
		JA4:       "t13d1614h2_8daaf6152771_5f6e7d8c9b0a",
	},
	"duckduckgo_browser": {
		Name:      "DuckDuckGo Browser",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/120.0.6099.230 DuckDuckGo/5 Safari/537.36",
		JA4:       "t13d1413h2_8daaf6152771_b0c1d2e3f4a5",
	},
	"ecosia_browser": {
		Name:      "Ecosia Browser",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Ecosia/14.0",
		JA4:       "t13d1715h2_8daaf6152771_6e7f8a9b0c1d",
	},
	"maxthon_browser": {
		Name:      "Maxthon Browser",
		JA3:       "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13,29-23-24,0",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Maxthon/6.2",
		JA4:       "t13d1413h2_8daaf6152771_4d5e6f7a8b9c",
	},
}

// GetBrowserProfile returns a predefined browser profile by name
func GetBrowserProfile(name string) (BrowserProfile, bool) {
	profile, ok := BrowserProfiles[name]
	return profile, ok
}

// GetBrowserJA3 returns the JA3 fingerprint for a browser profile
func GetBrowserJA3(profileName string) string {
	if profile, ok := BrowserProfiles[profileName]; ok {
		return profile.JA3
	}
	return ""
}

// GetBrowserJA4 returns the JA4 fingerprint for a browser profile
func GetBrowserJA4(profileName string) string {
	if profile, ok := BrowserProfiles[profileName]; ok {
		return profile.JA4
	}
	return ""
}

// GetBrowserUserAgent returns the User-Agent for a browser profile
func GetBrowserUserAgent(profileName string) string {
	if profile, ok := BrowserProfiles[profileName]; ok {
		return profile.UserAgent
	}
	return ""
}

// ListBrowserProfiles returns all available browser profile names
func ListBrowserProfiles() []string {
	profiles := make([]string, 0, len(BrowserProfiles))
	for name := range BrowserProfiles {
		profiles = append(profiles, name)
	}
	return profiles
}
