package passwd

import (
	"crypto/hmac"
	"fmt"

	"github.com/openwall/yescrypt-go"
	"github.com/pedroalbanese/gogost/gost34112012256"
)

type GostYesCrypt struct {
	Passwd
}

// Make an MD5Crypt password instance.
func NewGostYesCryptPasswd() PasswdInterface {
	m := new(GostYesCrypt)
	m.Magic = GOST_YES_CRYPT_MAGIC
	m.SetSCryptParams(11, 31)
	m.SaltLength = 22
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

// Sets the SCrypt params using integers.
func (a *GostYesCrypt) SetSCryptParams(N, r int) (err error) {
	Nval, err := IToA64(N)
	if err != nil {
		return
	}
	rval, err := IToA64(r)
	if err != nil {
		return
	}
	a.Params = fmt.Sprintf("j%c%c", Nval, rval)
	return
}

// Decode SCrypt params.
func (a *GostYesCrypt) DecodeSCryptParams() (N, r int) {
	b64 := []byte(a.Params)
	if len(b64) != 3 {
		return
	}
	N = AToI64(b64[1])
	r = AToI64(b64[2])
	return
}

// Hash a password with salt using gost yes crypt standard.
func (a *GostYesCrypt) Hash(password []byte, salt []byte) (hash []byte, err error) {
	output := []byte(fmt.Sprintf("%s%s$%s", YES_CRYPT_MAGIC, a.Params, salt))
	yescryptHash, err := yescrypt.Hash(password, output)
	if err != nil {
		return
	}
	bytes := SCryptBase64Decode(yescryptHash[len(output)+1:])

	h := gost34112012256.New()
	h.Write(password)
	hmacKey := h.Sum(nil)

	settings := []byte(fmt.Sprintf("%s%s$%s", a.Magic, a.Params, salt))
	hm := hmac.New(gost34112012256.New, hmacKey)
	hm.Write(settings)
	hmacKey = hm.Sum(nil)
	hm = hmac.New(gost34112012256.New, hmacKey)
	hm.Write(bytes)
	b64 := SCryptBase64Encode(hm.Sum(nil))

	hash = append(settings, '$')
	hash = append(hash, b64...)
	return
}

// Override the passwd hash with salt function to hash with gost yes crypt.
func (a *GostYesCrypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	hash, err = a.Hash(password, salt)
	return
}

// Hash an password using default parameters with Gost Yes Crypt.
func HashGostYesCryptPassword(password []byte) (hash []byte, err error) {
	passwd := NewGostYesCryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with Gost Yes Crypt.
func HashGostYesCryptPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewGostYesCryptPasswd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with Gost Yes Crypt.
func SHashGostYesCryptPassword(password string) (hash string, err error) {
	passwd := NewGostYesCryptPasswd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with Gost Yes Crypt.
func SHashGostYesCryptPasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewGostYesCryptPasswd()
	hash, err = passwd.SHashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}
