package passwd

import (
	"encoding/binary"
	"encoding/hex"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/md4"
)

type NTHash struct {
	Passwd
}

// Make NTHash password interface.
func NewNTPasswd() PasswdInterface {
	m := new(NTHash)
	m.Magic = NT_HASH_MAGIC
	// NT hashes has no salt, so we disable it.
	m.SaltLength = -1
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

// Encode UTF-8 bytes to UCS-2LE bytes.
// The NT hash uses UCS-2LE, so we need to convert for compatibility.
func (a *NTHash) UTF8ToUCS2LE(src []byte) []byte {
	// If there is no source data, return nil.
	if len(src) == 0 {
		return nil
	}

	// Convert bytes to UTF-8 runes.
	var runes []rune
	for len(src) > 0 {
		r, size := utf8.DecodeRune(src)
		runes = append(runes, r)
		src = src[size:]
	}

	// Re-encode UTF-8 to UTF-16.
	u := utf16.Encode(runes)

	// Setup new byte array to match length of UCS-2LE.
	dst := make([]byte, len(u)*2)

	// Index for inserting new bytes.
	i := 0

	// Convert each UTF-16 byte to UCS-2LE.
	for _, r := range u {
		binary.LittleEndian.PutUint16(dst[i:], r)
		i += 2
	}
	return dst
}

// Hash an NT compatible hash.
func (a *NTHash) Hash(password []byte) (hash []byte) {
	// Convert to UCS-2.
	ucsPw := a.UTF8ToUCS2LE(password)

	// Encoe MD4 hash with UCS-2LE bytes.
	h := md4.New()
	h.Write(ucsPw)
	buf := h.Sum(nil)

	// Hex encode MD4 hash.
	dst := make([]byte, hex.EncodedLen(len(buf)))
	hex.Encode(dst, buf)

	// Make crypt compatible hash from encoded hash.
	hash = append([]byte(a.Magic), '$')
	hash = append(hash, dst...)
	return
}

// Override the hash with salt function with one that encodes the NT hash, ignoring the salt.
func (a *NTHash) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	hash = a.Hash(password)
	return
}

// Hash an password using default parameters with NT.
func HashNTPassword(password []byte) (hash []byte, err error) {
	passwd := NewNTPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with NT.
func HashNTPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewNTPasswd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with NT.
func SHashNTPassword(password string) (hash string, err error) {
	passwd := NewNTPasswd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with NT.
func SHashNTPasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewNTPasswd()
	hash, err = passwd.SHashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}
