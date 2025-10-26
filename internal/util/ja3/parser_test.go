package ja3

import (
	"testing"
)

func TestParseJA3(t *testing.T) {
	tests := []struct {
		name    string
		ja3     string
		wantErr bool
	}{
		{
			name:    "Valid Chrome-like JA3",
			ja3:     "771,4865-4866-4867-49195-49199,0-23-65281-10-11,29-23,0",
			wantErr: false,
		},
		{
			name:    "Valid Firefox-like JA3",
			ja3:     "771,4865-4867-4866-49195-49199-52393-52392,0-23-65281-10-11-35-16-5-13,29-23-24,0",
			wantErr: false,
		},
		{
			name:    "Invalid format - too few parts",
			ja3:     "771,4865-4866",
			wantErr: true,
		},
		{
			name:    "Invalid format - too many parts",
			ja3:     "771,4865-4866,0-23,29-23,0,extra",
			wantErr: true,
		},
		{
			name:    "Empty string",
			ja3:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ParseJA3(tt.ja3)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseJA3() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && data == nil {
				t.Error("ParseJA3() returned nil data for valid input")
			}
		})
	}
}

func TestParseCipherName(t *testing.T) {
	tests := []struct {
		name       string
		cipherName string
		want       uint16
		wantErr    bool
	}{
		{
			name:       "TLS_AES_128_GCM_SHA256",
			cipherName: "TLS_AES_128_GCM_SHA256",
			want:       0x1301,
			wantErr:    false,
		},
		{
			name:       "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			cipherName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			want:       0xc02f,
			wantErr:    false,
		},
		{
			name:       "Unknown cipher",
			cipherName: "UNKNOWN_CIPHER",
			want:       0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCipherName(tt.cipherName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCipherName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseCipherName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildClientHelloSpecFromJA3(t *testing.T) {
	ja3 := "771,4865-4866-4867,0-23-65281,29-23,0"
	data, err := ParseJA3(ja3)
	if err != nil {
		t.Fatalf("Failed to parse JA3: %v", err)
	}

	spec, err := BuildClientHelloSpecFromJA3(data, "example.com")
	if err != nil {
		t.Fatalf("BuildClientHelloSpecFromJA3() error = %v", err)
	}

	if spec == nil {
		t.Fatal("BuildClientHelloSpecFromJA3() returned nil spec")
	}

	if len(spec.CipherSuites) != 3 {
		t.Errorf("Expected 3 cipher suites, got %d", len(spec.CipherSuites))
	}

	if spec.CipherSuites[0] != 4865 {
		t.Errorf("Expected first cipher suite to be 4865, got %d", spec.CipherSuites[0])
	}
}

func TestGetUTLSClientHelloID(t *testing.T) {
	tests := []struct {
		profile string
	}{
		{"chrome"},
		{"firefox"},
		{"safari"},
		{"edge"},
		{"ios"},
		{"android"},
		{"unknown"}, // Should default to chrome
	}

	for _, tt := range tests {
		t.Run(tt.profile, func(t *testing.T) {
			id := GetUTLSClientHelloID(tt.profile)
			// Just verify it doesn't panic and returns something
			if id.Str() == "" {
				t.Error("GetUTLSClientHelloID() returned empty ClientHelloID")
			}
		})
	}
}
