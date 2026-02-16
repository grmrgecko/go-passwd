package passwd

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	BCRYPT_MAX_HASH_SIZE = 23
)

// BCrypt implementation of the PasswdInterface.
type BCrypt struct {
	Passwd
}

// Creates a new BCrypt password instance.
func NewBCryptPasswd() PasswdInterface {
	m := new(BCrypt)
	m.Magic = BCRYPT_MAGIC
	// Default parameters: cost 14, minor 'a'.
	m.Params = "a$14"
	m.SaltLength = 16
	m.i = m
	return m
}

// IV for the 64 Blowfish encryption calls in bcrypt().
// It is the string "OrpheanBeholderScryDoubt" in big-endian bytes.
var magicCipherData = []byte{
	0x4f, 0x72, 0x70, 0x68,
	0x65, 0x61, 0x6e, 0x42,
	0x65, 0x68, 0x6f, 0x6c,
	0x64, 0x65, 0x72, 0x53,
	0x63, 0x72, 0x79, 0x44,
	0x6f, 0x75, 0x62, 0x74,
}

// Sets up the Blowfish cipher state with the expensive key expansion and salt mixing required by BCrypt.
func (a *BCrypt) setupBlowfishCipher(key []byte, cost uint32, salt []byte, bug bool, safety bool) (*BfCipher, error) {
	csalt, err := BCryptBase64Decode(salt)
	if err != nil {
		return nil, err
	}

	// Base64 decoding 22 chars produces 18 bytes (due to padding/alignment).
	// We must truncate to 16 bytes to match libxcrypt behavior.
	if len(csalt) > 16 {
		csalt = csalt[:16]
	}

	// Bug compatibility with C bcrypt implementations. They use the trailing
	// NULL in the key string during expansion.
	// We copy the key to prevent changing the underlying array.
	ckey := append(key[:len(key):len(key)], 0)

	c := NewBfCipher()
	c.SetKey(ckey, bug, safety)
	c.ExpandKeyWithSalt(csalt)

	var i, rounds uint64
	rounds = 1 << cost
	for i = 0; i < rounds; i++ {
		c.ExpandKey(ckey)
		c.ExpandKey(csalt)
	}

	return c, nil
}

// Generates a hash for the given password and salt using BCrypt.
func (a *BCrypt) Hash(password []byte, salt []byte) ([]byte, error) {
	// Defaults.
	var cost uint32 = 14
	var minor byte = 'a'

	// Parse parameters: "minor$cost".
	if a.Params != "" {
		idx := strings.Index(a.Params, "$")
		if idx != -1 {
			// Found separator.
			if idx > 0 {
				minor = a.Params[0]
			}
			// Parse cost.
			if len(a.Params) > idx+1 {
				cStr := a.Params[idx+1:]
				if c, cErr := strconv.ParseUint(cStr, 10, 32); cErr == nil {
					cost = uint32(c)
				} else {
					return nil, cErr
				}
			}
		}
	}
	if a.FollowStandards && (cost < 4 || cost > 31) {
		return nil, fmt.Errorf("bcrypt cost must be between 4 and 31")
	}

	// Ensure salt is truncated to 22 bytes.
	if len(salt) > 22 {
		salt = salt[:22]
	}

	cipherData := make([]byte, len(magicCipherData))
	copy(cipherData, magicCipherData)

	// Determine Blowfish flags based on minor version.
	var bug, safety bool
	switch minor {
	case 'a':
		safety = true
	case 'x':
		bug = true
	case 'b', 'y':
		// No bug, no safety hack needed (standard).
	default:
		return nil, fmt.Errorf("unsupported bcrypt minor version %q", minor)
	}

	c, err := a.setupBlowfishCipher(password, cost, salt, bug, safety)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 24; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(cipherData[i:i+8], cipherData[i:i+8])
		}
	}

	// Bug compatibility with C bcrypt implementations. We only encode 23 of
	// the 24 bytes encrypted.
	hashed := BCryptBase64Encode(cipherData[:BCRYPT_MAX_HASH_SIZE])

	// Format output.
	// $2<minor>$<cost>$<salt><hash>.
	magic := "$2"
	if minor != 0 {
		magic += string(minor)
	}

	output := fmt.Sprintf("%s$%02d$%s%s", magic, cost, salt, hashed)
	return []byte(output), nil
}

// Hashes the password using BCrypt with the provided salt.
func (a *BCrypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	return a.Hash(password, salt)
}

// Hash an password using default parameters with BCrypt.
func HashBCryptPassword(password []byte) (hash []byte, err error) {
	passwd := NewBCryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with BCrypt.
func HashBCryptPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewBCryptPasswd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with BCrypt.
func SHashBCryptPassword(password string) (hash string, err error) {
	passwd := NewBCryptPasswd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with BCrypt.
func SHashBCryptPasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewBCryptPasswd()
	hash, err = passwd.SHashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}
