package passwd

import (
	"fmt"

	"github.com/openwall/yescrypt-go"
)

type SCrypt struct {
	Passwd
}

// Make an MD5Crypt password instance.
func NewSCryptPasswd() PasswdInterface {
	m := new(SCrypt)
	m.Magic = S_CRYPT_MAGIC
	m.SetSCryptParams(14, 32, 1)
	m.SaltLength = 22
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

// Sets the SCrypt params using integers.
func (a *SCrypt) SetSCryptParams(N, r, p int) (err error) {
	var b64 []byte
	b64 = append(b64, iota64Encoding[N])
	b64 = append(b64, Base64Uint32Encode(uint32(r), 30)...)
	b64 = append(b64, Base64Uint32Encode(uint32(p), 30)...)
	a.Params = string(b64)
	return
}

// Decode SCrypt params.
func (a *SCrypt) DecodeSCryptParams() (N, r, p int) {
	b64 := []byte(a.Params)
	if len(b64) != 11 {
		return
	}
	N = AToI64(b64[0])
	r = int(Base64Uint32Decode(b64[1:6], 30))
	p = int(Base64Uint32Decode(b64[6:11], 30))
	return
}

// Hash a password with salt using scrypt standard.
func (a *SCrypt) Hash(password []byte, salt []byte) (hash []byte, err error) {
	N, r, p := a.DecodeSCryptParams()
	scryptHash, err := yescrypt.ScryptKey(password, salt, 1<<N, r, p, 32)

	b64 := SCryptBase64Encode(scryptHash)
	hash = []byte(fmt.Sprintf("%s%s%s$", a.Magic, a.Params, salt))
	hash = append(hash, b64...)
	return
}

// Override the passwd hash with salt function to hash with scrypt.
func (a *SCrypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	hash, err = a.Hash(password, salt)
	return
}

// Hash an password using default parameters with SCrypt.
func HashSCryptPassword(password []byte) (hash []byte, err error) {
	passwd := NewSCryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with SCrypt.
func HashSCryptPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewSCryptPasswd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with SCrypt.
func SHashSCryptPassword(password string) (hash string, err error) {
	passwd := NewSCryptPasswd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with SCrypt.
func SHashSCryptPasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewSCryptPasswd()
	hash, err = passwd.SHashPasswordWithSalt(salt, salt)
	if err != nil {
		return
	}
	return
}
