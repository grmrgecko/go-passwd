package passwd

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

const (
	SHA1_CRYPT_MAGIC     = "$sha1$"
	SHA1_SIZE            = 20
	SUN_MD5_MAGIC        = "$md5"
	MD5_CRYPT_MAGIC      = "$1$"
	MD5_SIZE             = 16
	NT_HASH_MAGIC        = "$3$"
	MD4_SIZE             = 16
	SHA256_CRYPT_MAGIC   = "$5$"
	SHA256_SIZE          = 32
	SHA512_CRYPT_MAGIC   = "$6$"
	SHA512_SIZE          = 64
	S_CRYPT_MAGIC        = "$7$"
	YES_CRYPT_MAGIC      = "$y$"
	GOST_YES_CRYPT_MAGIC = "$gy$"
	BCRYPT_MAGIC         = "$2"
	BCRYPT_SALT_LENGTH   = 22
)

// Standard protocol for working with all hash algorithms.
type PasswdInterface interface {
	SetParams(p string)
	SetSalt(s []byte)
	GenerateSalt() ([]byte, error)
	HashPassword(password []byte) (hash []byte, err error)
	HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error)
	SHashPassword(password string) (hash string, err error)
	SHashPasswordWithSalt(password string, salt string) (hash string, err error)
}

// Base structure.
type Passwd struct {
	Magic      string
	Params     string
	SaltLength int
	Salt       []byte
	i          PasswdInterface
}

// Get a password interface based on hash settings string.
func NewPasswd(settings string) (PasswdInterface, error) {
	// SHA1 $sha1$<iterations>$<salt>[$]
	if strings.HasPrefix(settings, SHA1_CRYPT_MAGIC) {
		// Split by $ to get options.
		s := strings.Split(settings[len(SHA1_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 2 {
			return nil, errors.New("Too few parameters for SHA1 hash")
		}

		// Confirm that the iterations can be parsed.
		iterations, err := strconv.ParseUint(s[0], 10, 64)
		if err != nil {
			return nil, err
		}

		// Make the interface.
		passwd := NewSHA1Passwd()
		passwd.SetParams(strconv.FormatUint(iterations, 10))
		passwd.SetSalt([]byte(s[1]))
		return passwd, nil
	}

	// Sun MD5 $md5[,rounds=<iterations>]$<salt>[$]
	if strings.HasPrefix(settings, SUN_MD5_MAGIC) {
		s := strings.Split(settings[len(SUN_MD5_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 2 {
			return nil, errors.New("Too few parameters for Sun MD5 hash")
		}

		// Parse iterations from parameter.
		if s[0] != "" && s[0][0] == ',' {
			s[0] = s[0][1:]
		}
		var iterations uint64
		if s[0] != "" {
			_, err := fmt.Sscanf(s[0], "rounds=%d", &iterations)
			if err != nil {
				return nil, err
			}
		}

		// Make the interface.
		passwd := NewSunMD5Passwd()
		passwd.SetParams(s[0])
		passwd.SetSalt([]byte(s[1]))
		return passwd, nil
	}

	// MD5 $1$<salt>[$]
	if strings.HasPrefix(settings, MD5_CRYPT_MAGIC) {
		s := strings.Split(settings[len(MD5_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 1 {
			return nil, errors.New("Too few parameters for MD5 hash")
		}

		// Make the interface.
		passwd := NewMD5CryptPasswd()
		passwd.SetSalt([]byte(s[0]))
		return passwd, nil
	}

	// NT $3$[$]
	if strings.HasPrefix(settings, NT_HASH_MAGIC) {
		// Make the interface.
		passwd := NewNTPasswd()
		return passwd, nil
	}

	// SHA256 $5$[rounds=<iterations>$]<salt>[$]
	if strings.HasPrefix(settings, SHA256_CRYPT_MAGIC) {
		s := strings.Split(settings[len(SHA256_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 1 {
			return nil, errors.New("Too few parameters for SHA256 hash")
		}

		// If rounds set, parse it.
		var iterations uint64
		if strings.HasPrefix(s[0], "rounds=") {
			_, err := fmt.Sscanf(s[0], "rounds=%d", &iterations)
			if err != nil {
				return nil, err
			}
			if len(s) < 2 {
				return nil, errors.New("Too few parameters for SHA256 hash")
			}
			s[0] = s[1]
		}

		// Make the interface.
		passwd := NewSHA256CryptPasswd()
		if iterations != 0 {
			passwd.SetParams(fmt.Sprintf("rounds=%d", iterations))
		}
		passwd.SetSalt([]byte(s[0]))
		return passwd, nil
	}

	// SHA512 $6$[rounds=<iterations>$]<salt>[$]
	if strings.HasPrefix(settings, SHA512_CRYPT_MAGIC) {
		s := strings.Split(settings[len(SHA512_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 1 {
			return nil, errors.New("Too few parameters for SHA512 hash")
		}

		// If rounds set, parse it.
		var iterations uint64
		if strings.HasPrefix(s[0], "rounds=") {
			_, err := fmt.Sscanf(s[0], "rounds=%d", &iterations)
			if err != nil {
				return nil, err
			}
			if len(s) < 2 {
				return nil, errors.New("Too few parameters for SHA512 hash")
			}
			s[0] = s[1]
		}

		// Make the interface.
		passwd := NewSHA512CryptPasswd()
		if iterations != 0 {
			passwd.SetParams(fmt.Sprintf("rounds=%d", iterations))
		}
		passwd.SetSalt([]byte(s[0]))
		return passwd, nil
	}

	// SCrypt $7$<N><r><p><salt>[$]
	if strings.HasPrefix(settings, S_CRYPT_MAGIC) {
		s := strings.Split(settings[len(S_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 1 {
			return nil, errors.New("Too few parameters for SCrypt hash")
		}

		if len(s[0]) < 12 {
			return nil, errors.New("Too few characters in salt for SCrypt")
		}
		params := s[0][:11]
		salt := s[0][11:]

		// Make the interface.
		passwd := NewSCryptPasswd()
		passwd.SetParams(params)
		passwd.SetSalt([]byte(salt))
		return passwd, nil
	}

	// Yes Crypt $y$j<N><r>$<salt>[$]
	if strings.HasPrefix(settings, YES_CRYPT_MAGIC) {
		s := strings.Split(settings[len(YES_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 2 {
			return nil, errors.New("Too few parameters for Yes Crypt hash")
		}

		if len(s[0]) != 3 {
			return nil, errors.New("Invalid length for Yes Crypt parameters")
		}

		// Make the interface.
		passwd := NewYesCryptPasswd()
		passwd.SetParams(s[0])
		passwd.SetSalt([]byte(s[1]))
		return passwd, nil
	}

	// Gost Yes Crypt $gy$j<N><r>$<salt>[$]
	if strings.HasPrefix(settings, GOST_YES_CRYPT_MAGIC) {
		s := strings.Split(settings[len(GOST_YES_CRYPT_MAGIC):], "$")

		// If less than 2 options, this is not a valid setting.
		if len(s) < 2 {
			return nil, errors.New("Too few parameters for Gost Yes Crypt hash")
		}

		if len(s[0]) != 3 {
			return nil, errors.New("Invalid length for Gost Yes Crypt parameters")
		}

		// Make the interface.
		passwd := NewGostYesCryptPasswd()
		passwd.SetParams(s[0])
		passwd.SetSalt([]byte(s[1]))
		return passwd, nil
	}

	// BCrypt.
	// $2[abxy]$[cost]$[salt][hash]
	if strings.HasPrefix(settings, BCRYPT_MAGIC) {
		passwd := NewBCryptPasswd()

		// Magic prefix is trimmed to handle the rest of the string.
		s := settings[len(BCRYPT_MAGIC):]

		// The last dollar sign separates the parameters from the salt.
		lastDollar := strings.LastIndex(s, "$")

		if lastDollar == -1 {
			return nil, errors.New("Invalid bcrypt hash format: missing separator")
		}

		// Parameters are everything before the last dollar sign.
		passwd.SetParams(s[:lastDollar])

		// Salt is the first BCRYPT_SALT_LENGTH bytes after the last dollar sign.
		saltStart := lastDollar + 1
		if len(s) < saltStart+BCRYPT_SALT_LENGTH {
			return nil, errors.New("Invalid bcrypt hash format: salt too short")
		}

		passwd.SetSalt([]byte(s[saltStart : saltStart+BCRYPT_SALT_LENGTH]))

		return passwd, nil
	}

	// End of the line.
	return nil, errors.New("No valid matching algorithm")
}

// Check a password hash against a password.
func CheckPassword(hash []byte, password []byte) (bool, error) {
	passwd, err := NewPasswd(string(hash))
	if err != nil {
		return false, err
	}
	newHash, err := passwd.HashPassword(password)
	if err != nil {
		return false, err
	}
	if bytes.Equal(hash, newHash) {
		return true, nil
	}
	return false, nil
}

// Check a password hash against a password string.
func SCheckPassword(hash string, password string) (bool, error) {
	passwd, err := NewPasswd(hash)
	if err != nil {
		return false, err
	}
	newHash, err := passwd.SHashPassword(password)
	if err != nil {
		return false, err
	}
	if hash == newHash {
		return true, nil
	}
	log.Printf("Hash does not match: %s != %s", hash, newHash)
	return false, nil
}

// Used internally for salt generation.
func generateRandomBytes(n uint) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Set parameters for password generation. Typically used for iterations, but also used for yes crypt configuration.
func (a *Passwd) SetParams(p string) {
	a.Params = p
}

// Set a salt for hashing, an empty salt will generate a new one.
func (a *Passwd) SetSalt(s []byte) {
	a.Salt = s
}

// Generate a salt based on configs for this paassword algorithm.
func (a *Passwd) GenerateSalt() ([]byte, error) {
	var salt []byte
	if a.SaltLength > -1 {
		if a.SaltLength == 0 {
			a.SaltLength = 16
		}
		rawSalt, err := generateRandomBytes(uint(a.SaltLength))
		if err != nil {
			return nil, err
		}
		salt = Base64Encode(rawSalt)
	}
	return salt, nil
}

// Hash a password.
func (a *Passwd) HashPassword(password []byte) (hash []byte, err error) {
	if len(a.Salt) == 0 {
		salt, err := a.GenerateSalt()
		if err != nil {
			return nil, err
		}
		a.Salt = salt
	}

	if a.i != nil {
		hash, err = a.i.HashPasswordWithSalt(password, a.Salt)
	} else {
		hash, err = a.HashPasswordWithSalt(password, a.Salt)
	}
	return
}

// Hash a password with a custom salt.
func (a *Passwd) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	err = errors.New("hash algorithm is not implemented")
	return
}

// Hash a password string.
func (a *Passwd) SHashPassword(password string) (hash string, err error) {
	hashb, err := a.HashPassword([]byte(password))
	hash = string(hashb)
	return
}

// Hash a password string with a custom salt.
func (a *Passwd) SHashPasswordWithSalt(password string, salt string) (hash string, err error) {
	var hashb []byte
	if a.i != nil {
		hashb, err = a.i.HashPasswordWithSalt([]byte(password), []byte(salt))
	} else {
		hashb, err = a.HashPasswordWithSalt([]byte(password), []byte(salt))
	}
	hash = string(hashb)
	return
}
