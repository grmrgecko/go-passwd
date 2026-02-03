package passwd

import (
	"encoding/base64"
	"errors"
	"hash"
)

// The non-standard alphabet for crypt base64 encoding.
const iota64Encoding = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// Base64 to integer encoding table.
var atoi64Partial = [...]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	64, 64, 64, 64, 64, 64, 64,
	12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
	64, 64, 64, 64, 64, 64,
	38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
}

// Append base64 for provided uint.
func Base64Append(dst []byte, v uint, n int) []byte {
	// Until we finish the number of rounds specified,
	// loop and encode to base64.
	for n > 0 {
		// Append base64 of current bit.
		dst = append(dst, iota64Encoding[v&0x3F])
		// Jump to the next bit for encoding.
		v >>= 6
		n -= 1
	}
	// Return new byte array.
	return dst
}

// Encode to crypt base64 with flawed logic that misses bytes.
// This is used for SHA1 crypt algorithm.
func SHA1Base64Encode(src []byte) []byte {
	size := len(src)
	var b64 []byte
	var i int
	for i = 0; i < size-3; i += 3 {
		l := uint(src[i])<<16 |
			uint(src[i+1])<<8 |
			uint(src[i+2])
		b64 = Base64Append(b64, l, 4)
	}
	var l uint
	if size-i == 2 {
		l = uint(src[i])<<16 |
			uint(src[i+1])<<8 |
			uint(src[0])
		b64 = Base64Append(b64, l, 4)
	}
	return b64
}

// Encode to crypt base64.
func Base64Encode(src []byte) []byte {
	size := len(src)
	var b64 []byte
	var i int
	for i = 0; i <= size-3; i += 3 {
		l := uint(src[i])<<16 |
			uint(src[i+1])<<8 |
			uint(src[i+2])
		b64 = Base64Append(b64, l, 4)
	}
	remaining := size - i
	if remaining == 2 {
		l := uint(src[i])<<8 |
			uint(src[i+1])
		b64 = Base64Append(b64, l, 3)
	} else if remaining == 1 {
		l := uint(src[i])
		b64 = Base64Append(b64, l, 2)
	}
	return b64
}

// Decode from crypt base64.
func Base64Decode(src []byte) ([]byte, error) {
	size := len(src)
	if size == 0 {
		return []byte{}, nil
	}
	if size%4 == 1 {
		return nil, errors.New("invalid base64 length")
	}

	// Output buffer guessing.
	// We can't know exact size easily due to the legacy 4->2 behavior vs 4->3,
	// but (size/4)*3 is a safe lower bound, capacity can be larger.
	dst := make([]byte, 0, (size/4)*3+3)
	var i int
	for i = 0; i < size-4; i += 4 {
		var v uint
		for j := 0; j < 4; j++ {
			c := AToI64(src[i+j])
			if c > 63 {
				return nil, errors.New("invalid character in base64")
			}
			v |= uint(c) << (uint(j) * 6)
		}
		dst = append(dst, byte(v>>16), byte(v>>8), byte(v))
	}
	// Handle last block (can be partial)
	remaining := size - i
	var v uint
	for j := 0; j < remaining; j++ {
		c := AToI64(src[i+j])
		if c > 63 {
			return nil, errors.New("invalid character in base64")
		}
		v |= uint(c) << (uint(j) * 6)
	}

	if remaining == 4 {
		// 4 chars -> 3 bytes
		dst = append(dst, byte(v>>16), byte(v>>8), byte(v))
	} else if remaining == 3 {
		// 3 chars -> 2 bytes
		dst = append(dst, byte(v>>8), byte(v))
	} else if remaining == 2 {
		// 2 chars -> 1 byte
		dst = append(dst, byte(v))
	}
	return dst, nil
}

// Takes a prior hash, and recycles bytes until the length provided is covered.
func HashBlockRecycle(h hash.Hash, block []byte, len int) {
	size := h.BlockSize()
	var cnt int
	for cnt = len; cnt > size; cnt -= size {
		h.Write(block)
	}
	// Remaining characters of the length, add sub slice here.
	h.Write(block[:cnt])
}

// Convert base64 byte to integer value.
func AToI64(c byte) (val int) {
	if c >= '.' && c <= 'z' {
		val = int(atoi64Partial[c-'.'])
	}
	return
}

// Convert integer to bae64.
func IToA64(N int) (val byte, err error) {
	if N > 64 {
		err = errors.New("maximum itoa64 value is 64")
		return
	}
	Nb := byte(N)
	for i, b := range atoi64Partial {
		if b == Nb {
			val = '.' + byte(i)
		}
	}
	return
}

// Get the power of 2 value.
func N2log2(N uint64) (N_log2 int) {
	if N < 2 {
		return
	}

	// Find power by bit shifting until shifting results in 0.
	N_log2 = 2
	for N>>N_log2 != 0 {
		N_log2++
	}
	N_log2--

	// If the result of removing one power level ends up resulting in a shift of not 1, return 0.
	if N>>N_log2 != 1 {
		return 0
	}

	return
}

// Encode uint32 into base64 at a fixed length.
func Base64Uint32Encode(src, srcbits uint32) (b64 []byte) {
	var bits uint32

	for bits = 0; bits < srcbits; bits += 6 {
		b64 = append(b64, iota64Encoding[src&0x3F])
		src >>= 6
	}

	if src != 0 {
		return []byte{}
	}
	return
}

// Decode uint32 from base64 at a fixed length.
func Base64Uint32Decode(src []byte, dstbits uint32) (dst uint32) {
	var bits uint32
	var i uint
	for bits = 0; bits < dstbits; bits += 6 {
		c := AToI64(src[i])
		i++
		if c > 63 {
			return 0
		}
		dst |= uint32(c << bits)
	}
	return
}

// Encode base64 in the format used for SCrypt hashes.
func SCryptBase64Encode(src []byte) []byte {
	dst := make([]byte, 0, (len(src)*8+5)/6)
	for i := 0; i < len(src); {
		var val uint32
		var bits int32
		for ; bits < 24 && i < len(src); bits += 8 {
			val |= uint32(src[i]) << bits
			i++
		}
		for ; bits > 0; bits -= 6 {
			dst = append(dst, iota64Encoding[val&0x3F])
			val >>= 6
		}
	}
	return dst
}

// Decode base64 in the format used for SCrypt hashes.
func SCryptBase64Decode(src []byte) []byte {
	dst := make([]byte, 0, len(src)*3/4)
	for i := 0; i < len(src); {
		var val uint32
		var bits int32
		for ; bits < 24 && i < len(src); bits += 6 {
			c := AToI64(src[i])
			if c > 63 {
				return nil
			}
			i++
			val |= uint32(c) << bits
		}
		if bits < 12 {
			return nil
		}
		for ; bits >= 8; bits -= 8 {
			dst = append(dst, byte(val))
			val >>= 8
		}
		if val != 0 {
			return nil
		}
	}
	return dst
}

// Encode MD5 result to MD5 crypt base64.
func MD5Base64Encode(src []byte) []byte {
	// The way the crypt standards work with base64 encoding of MD5 is odd, because the
	// last round rotates some of the hash bytes positions. So we must have this custom
	// function just to encode MD5 hashes to base64.
	var b64 []byte
	l := uint(src[0])<<16 | uint(src[6])<<8 | uint(src[12])
	b64 = Base64Append(b64, l, 4)
	l = uint(src[1])<<16 | uint(src[7])<<8 | uint(src[13])
	b64 = Base64Append(b64, l, 4)
	l = uint(src[2])<<16 | uint(src[8])<<8 | uint(src[14])
	b64 = Base64Append(b64, l, 4)
	l = uint(src[3])<<16 | uint(src[9])<<8 | uint(src[15])
	b64 = Base64Append(b64, l, 4)
	l = uint(src[4])<<16 | uint(src[10])<<8 | uint(src[5])
	b64 = Base64Append(b64, l, 4)
	l = uint(src[11])
	b64 = Base64Append(b64, l, 2)
	return b64
}

// Decode MD5 result from MD5 crypt base64.
func MD5Base64Decode(src []byte) ([]byte, error) {
	if len(src) != 22 {
		return nil, errors.New("invalid MD5 base64 length")
	}

	dst := make([]byte, 16)
	decode4 := func(b []byte) (uint, error) {
		var v uint
		for j := 0; j < 4; j++ {
			c := AToI64(b[j])
			if c > 63 {
				return 0, errors.New("invalid character in base64")
			}
			v |= uint(c) << (uint(j) * 6)
		}
		return v, nil
	}

	var v uint
	var err error

	v, err = decode4(src[0:4])
	if err != nil {
		return nil, err
	}
	dst[12], dst[6], dst[0] = byte(v), byte(v>>8), byte(v>>16)

	v, err = decode4(src[4:8])
	if err != nil {
		return nil, err
	}
	dst[13], dst[7], dst[1] = byte(v), byte(v>>8), byte(v>>16)

	v, err = decode4(src[8:12])
	if err != nil {
		return nil, err
	}
	dst[14], dst[8], dst[2] = byte(v), byte(v>>8), byte(v>>16)

	v, err = decode4(src[12:16])
	if err != nil {
		return nil, err
	}
	dst[15], dst[9], dst[3] = byte(v), byte(v>>8), byte(v>>16)

	v, err = decode4(src[16:20])
	if err != nil {
		return nil, err
	}
	dst[5], dst[10], dst[4] = byte(v), byte(v>>8), byte(v>>16)

	// Last 2 characters
	c0 := AToI64(src[20])
	c1 := AToI64(src[21])
	if c0 > 63 || c1 > 63 {
		return nil, errors.New("invalid character in base64")
	}
	v = uint(c0) | uint(c1)<<6
	dst[11] = byte(v)

	return dst, nil
}

// The crypt standard likes to rotate bits in base64,
// although it doesn't really do anything for brute force protection.
// This performs the rotation algorithm.
func Base64RotateEncode(src []byte, order bool) []byte {
	var b64 []byte
	l := len(src)
	// Setup indexes.
	// Used for the loop.
	i := 0
	// Index A.
	ia := 0
	// Index C, should be byte length divided by 3 to ensure we start a the 3rd point.
	ib := l / 3
	// Index C is just B doubled.
	ic := ib + ib
	// Index D is used to determine which iteration we're on.
	id := 0
	// Loop until we reach the last index that fits all 3 values to b64.
	for ; i < l-3; i += 3 {
		var a, b, c int
		// Depending on index D, rotate the A, B, and C indexes.
		// I am not sure why we are rotating byte input, it doesn't do anything
		// with regards to brute force protection. Someone can just reverse the
		// byte order to decode the base64 back down to binary, then use the binary
		// for brute force attacks.
		if order {
			switch id % 3 {
			case 0:
				a = ia
				b = ib
				c = ic
			case 1:
				a = ib
				b = ic
				c = ia
			case 2:
				a = ic
				b = ia
				c = ib
			}
		} else {
			switch id % 3 {
			case 0:
				a = ia
				b = ib
				c = ic
			case 1:
				a = ic
				b = ia
				c = ib
			case 2:
				a = ib
				b = ic
				c = ia
			}
		}

		// For this round, append the base64.
		l := uint(src[a])<<16 | uint(src[b])<<8 | uint(src[c])
		b64 = Base64Append(b64, l, 4)

		// Increment the indexes.
		ia++
		ib++
		ic++
		id++
	}
	// For the remaining bytes, append as needed.
	if l-i == 2 {
		l := uint(0)<<16 | uint(src[l-1])<<8 | uint(src[l-2])
		b64 = Base64Append(b64, l, 3)
	} else {
		l := uint(0)<<16 | uint(0)<<8 | uint(src[l-1])
		b64 = Base64Append(b64, l, 2)
	}
	// Return the base64.
	return b64
}

// Decode from rotated base64.
func Base64RotateDecode(src []byte, order bool) ([]byte, error) {
	b64len := len(src)
	var l int
	if b64len%4 == 0 {
		l = (b64len / 4) * 3
	} else if b64len%4 == 3 {
		l = (b64len/4)*3 + 2
	} else if b64len%4 == 2 {
		l = (b64len/4)*3 + 1
	} else {
		return nil, errors.New("invalid base64 length")
	}

	dst := make([]byte, l)
	ia := 0
	ib := l / 3
	ic := ib + ib
	id := 0
	i := 0      // index in src (base64)
	outIdx := 0 // index for original bytes loop (mimicking i in Encode)

	// Process blocks of 4 -> 3
	for ; outIdx < l-3; outIdx += 3 {
		var v uint
		for j := 0; j < 4; j++ {
			c := AToI64(src[i+j])
			if c > 63 {
				return nil, errors.New("invalid character in base64")
			}
			v |= uint(c) << (uint(j) * 6)
		}
		i += 4

		var a, b, c int
		if order {
			switch id % 3 {
			case 0:
				a, b, c = ia, ib, ic
			case 1:
				a, b, c = ib, ic, ia
			case 2:
				a, b, c = ic, ia, ib
			}
		} else {
			switch id % 3 {
			case 0:
				a, b, c = ia, ib, ic
			case 1:
				a, b, c = ic, ia, ib
			case 2:
				a, b, c = ib, ic, ia
			}
		}
		dst[a] = byte(v >> 16)
		dst[b] = byte(v >> 8)
		dst[c] = byte(v)
		ia++
		ib++
		ic++
		id++
	}

	// Process remainder
	if l-outIdx == 2 {
		var v uint
		for j := 0; j < 3; j++ {
			c := AToI64(src[i+j])
			if c > 63 {
				return nil, errors.New("invalid character in base64")
			}
			v |= uint(c) << (uint(j) * 6)
		}
		dst[l-1] = byte(v >> 8)
		dst[l-2] = byte(v)
	} else if l-outIdx == 1 {
		var v uint
		for j := 0; j < 2; j++ {
			c := AToI64(src[i+j])
			if c > 63 {
				return nil, errors.New("invalid character in base64")
			}
			v |= uint(c) << (uint(j) * 6)
		}
		dst[l-1] = byte(v)
	}
	return dst, nil
}

// BCrypt specific alphabet.
const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcryptEncoding = base64.NewEncoding(bcryptAlphabet).WithPadding(base64.NoPadding)

// Encode to bcrypt base64.
func BCryptBase64Encode(src []byte) []byte {
	n := bcryptEncoding.EncodedLen(len(src))
	dst := make([]byte, n)
	bcryptEncoding.Encode(dst, src)
	return dst
}

// Decode from bcrypt base64.
func BCryptBase64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, bcryptEncoding.DecodedLen(len(src)))
	n, err := bcryptEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
