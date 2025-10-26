package fingerprint

// GREASE (Generate Random Extensions And Sustain Extensibility) values
// RFC 8701: https://tools.ietf.org/html/rfc8701
//
// GREASE values are reserved values that can be used in TLS handshakes
// to test that implementations properly ignore unknown values.

// GREASEValues contains all standard GREASE values
var GREASEValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
	0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
	0xcaca, 0xdada, 0xeaea, 0xfafa,
}

// greaseMap for fast lookup
var greaseMap map[uint16]bool

func init() {
	greaseMap = make(map[uint16]bool, len(GREASEValues))
	for _, v := range GREASEValues {
		greaseMap[v] = true
	}
}

// IsGREASE checks if a value is a GREASE value
func IsGREASE(value uint16) bool {
	return greaseMap[value]
}

// FilterGREASE removes GREASE values from a slice
func FilterGREASE(values []uint16) []uint16 {
	if len(values) == 0 {
		return values
	}

	result := make([]uint16, 0, len(values))
	for _, v := range values {
		if !IsGREASE(v) {
			result = append(result, v)
		}
	}
	return result
}

// PreserveGREASE keeps GREASE values in their original positions
// Returns a new slice with GREASE values preserved
func PreserveGREASE(values []uint16) []uint16 {
	if len(values) == 0 {
		return values
	}

	result := make([]uint16, len(values))
	copy(result, values)
	return result
}

// InjectGREASE adds GREASE values to a slice at random positions
// This is useful for making fingerprints look more like real browsers
func InjectGREASE(values []uint16, positions []int) []uint16 {
	if len(values) == 0 || len(positions) == 0 {
		return values
	}

	result := make([]uint16, 0, len(values)+len(positions))
	greaseIdx := 0
	valueIdx := 0

	for i := 0; i <= len(values)+len(positions); i++ {
		// Check if we should inject GREASE at this position
		shouldInject := false
		for _, pos := range positions {
			if i == pos && greaseIdx < len(GREASEValues) {
				shouldInject = true
				break
			}
		}

		if shouldInject {
			result = append(result, GREASEValues[greaseIdx%len(GREASEValues)])
			greaseIdx++
		} else if valueIdx < len(values) {
			result = append(result, values[valueIdx])
			valueIdx++
		}
	}

	return result
}

// CountGREASE counts the number of GREASE values in a slice
func CountGREASE(values []uint16) int {
	count := 0
	for _, v := range values {
		if IsGREASE(v) {
			count++
		}
	}
	return count
}

// GetGREASEPositions returns the positions of GREASE values in a slice
func GetGREASEPositions(values []uint16) []int {
	positions := make([]int, 0)
	for i, v := range values {
		if IsGREASE(v) {
			positions = append(positions, i)
		}
	}
	return positions
}

// HasGREASE checks if a slice contains any GREASE values
func HasGREASE(values []uint16) bool {
	for _, v := range values {
		if IsGREASE(v) {
			return true
		}
	}
	return false
}

// NormalizeWithGREASE replaces all GREASE values with a single standard GREASE value
// This is useful for fingerprint comparison where GREASE placement matters but value doesn't
func NormalizeWithGREASE(values []uint16) []uint16 {
	if len(values) == 0 {
		return values
	}

	result := make([]uint16, len(values))
	for i, v := range values {
		if IsGREASE(v) {
			result[i] = 0x0a0a // Use first GREASE value as standard
		} else {
			result[i] = v
		}
	}
	return result
}
