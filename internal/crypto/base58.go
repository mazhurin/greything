package crypto

import "errors"

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes bytes to base58btc (no multibase prefix).
func base58Encode(b []byte) string {
	// big integer style convert base256 -> base58, little-endian digits
	digits := []int{0}
	for _, v := range b {
		carry := int(v)
		for j := 0; j < len(digits); j++ {
			carry += digits[j] << 8
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, carry%58)
			carry /= 58
		}
	}

	// handle leading zeros
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}

	out := make([]byte, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out[i] = '1'
	}
	for i := 0; i < len(digits); i++ {
		out[len(out)-1-i] = b58Alphabet[digits[i]]
	}
	return string(out)
}

    func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty base58")
	}
	index := make(map[rune]int, len(b58Alphabet))
	for i, r := range b58Alphabet {
		index[r] = i
	}

	// big integer decode into base256 little-endian bytes
	num := []int{0}
	for _, r := range s {
		val, ok := index[r]
		if !ok {
			return nil, errors.New("invalid base58 char")
		}
		carry := val
		for j := 0; j < len(num); j++ {
			carry += num[j] * 58
			num[j] = carry & 0xff
			carry >>= 8
		}
		for carry > 0 {
			num = append(num, carry&0xff)
			carry >>= 8
		}
	}

	// leading zeros
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}

	out := make([]byte, zeros+len(num))
	for i := 0; i < len(num); i++ {
		out[len(out)-1-i] = byte(num[i])
	}
	return out, nil
}

// Base58Encode encodes bytes to base58btc (without multibase prefix).
// Exported for CLI tools and tests.
func Base58Encode(b []byte) string {
	return base58Encode(b)
}

// Base58Decode decodes base58btc string (without multibase prefix).
// Exported for CLI tools and tests.
func Base58Decode(s string) ([]byte, error) {
	return base58Decode(s)
}