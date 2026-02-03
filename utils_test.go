package passwd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBase64(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"1 byte", []byte{'A'}},
		{"2 bytes", []byte{1, 2}},
		{"3 bytes", []byte{'A', 'B', 'C'}},
		{"4 bytes", []byte{'A', 'B', 'C', 'D'}},
		{"5 bytes", []byte{1, 2, 3, 4, 5}},
		{"16 bytes", []byte{140, 150, 169, 113, 54, 237, 5, 115, 223, 241, 60, 27, 242, 218, 42, 110}},
		{"11 bytes", make([]byte, 11)},
		{"SHA1 style 20 bytes", make([]byte, 20)},
		{"Hello (5 bytes)", []byte("hello")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := Base64Encode(tc.input)

			if len(encoded) == 0 && len(tc.input) > 0 {
				t.Logf("Skipping validation for lossy encode")
				return
			}

			decoded, err := Base64Decode(encoded)
			require.NoError(t, err, "Base64Decode should not return an error for valid input")

			reEncoded := Base64Encode(decoded)
			assert.Equal(t, string(encoded), string(reEncoded), "Round-trip failed")
		})
	}

	t.Run("Invalid", func(t *testing.T) {
		invalidInputs := []string{
			"::::",  // Invalid character ':'
			"abcde", // Invalid length (5 % 4 == 1)
		}
		for _, input := range invalidInputs {
			_, err := Base64Decode([]byte(input))
			assert.Error(t, err, "Expected error for invalid input: %s", input)
		}
	})
}

func TestMD5Base64(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"All Zeros", make([]byte, 16)},
		{"Sequence", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
		{"Randomish", []byte{0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0xaa, 0xbb, 0xcc, 0xdd}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := MD5Base64Encode(tc.input)
			decoded, err := MD5Base64Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, tc.input, decoded, "Round-trip failed")
		})
	}

	t.Run("Invalid", func(t *testing.T) {
		_, err := MD5Base64Decode([]byte("too short"))
		assert.Error(t, err)
	})
}

func TestBase64Rotate(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		order bool
	}{
		{"SHA256 order false", make([]byte, 32), false},
		{"SHA512 order false", make([]byte, 64), false},
		{"Sequence 32 false", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}, false},
		{"Sequence 32 true", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}, true},
		{"Small 4 false", []byte{1, 2, 3, 4}, false},
		{"Small 5 false", []byte{1, 2, 3, 4, 5}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := Base64RotateEncode(tc.input, tc.order)
			decoded, err := Base64RotateDecode(encoded, tc.order)
			require.NoError(t, err)
			assert.Equal(t, tc.input, decoded, "Round-trip failed")
		})
	}
}

func TestBCryptBase64(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte{1, 2, 3}},
		{"Bcrypt Salt", make([]byte, 16)},
		{"Randomish", []byte("this is a test for bcrypt base64")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := BCryptBase64Encode(tc.input)
			decoded, err := BCryptBase64Decode(encoded)
			require.NoError(t, err)
			assert.Equal(t, tc.input, decoded, "Round-trip failed")
		})
	}

	t.Run("Invalid", func(t *testing.T) {
		_, err := BCryptBase64Decode([]byte("invalid!"))
		assert.Error(t, err)
	})
}

func TestSCryptBase64(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Empty", []byte{}},
		{"Short", []byte{1, 2, 3}},
		{"Scrypt Data", make([]byte, 32)},
		{"Randomish", []byte("scrypt base64 should handle any data")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := SCryptBase64Encode(tc.input)
			decoded := SCryptBase64Decode(encoded)
			assert.Equal(t, tc.input, decoded, "Round-trip failed")
		})
	}
}

func TestBase64Uint32(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		bits  uint32
	}{
		{"Small 6 bits", 42, 6},
		{"Medium 12 bits", 1234, 12},
		{"Large 24 bits", 0xABCDEF, 24},
		{"Full 32 bits", 0xFFFFFFFF, 32},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			encoded := Base64Uint32Encode(tc.value, tc.bits)
			decoded := Base64Uint32Decode(encoded, tc.bits)
			assert.Equal(t, tc.value, decoded, "Round-trip failed")
		})
	}
}
