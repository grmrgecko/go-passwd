package passwd

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"strconv"
)

type SHA1Crypt struct {
	Passwd
}

func NewSHA1Passwd() PasswdInterface {
	m := new(SHA1Crypt)
	m.Magic = SHA1_CRYPT_MAGIC
	m.Params = "262144"
	m.i = m
	return m
}

// PBKDF1 with SHA1 crypt algorithm.
func (a *SHA1Crypt) Hash(password []byte, salt []byte, iterations uint64) (hash []byte) {
	// We store the magic bytes as a string as we use sprintf to
	// encode the outputs and easily translate the iterations
	// from an uint64 to a string.
	magic := a.Magic

	// The first bit we encode into the hmac is the salt,
	// magic string, and iterations of hmac rounds.
	output := fmt.Sprintf("%s%s%d", salt, magic, iterations)

	// Setup hmac with the password as the key.
	hm := hmac.New(sha1.New, password)

	// Write the salt and parameters to the hmac.
	hm.Write([]byte(output))

	// Get the first sum for the iterrations.
	buf := hm.Sum(nil)

	// Iterate the hmac to the specified number of iterations.
	for i := uint64(1); i < iterations; i++ {
		// Setup the hmac for this iteration.
		hm.Reset()

		// Feed back in the buffer from the last iteration.
		hm.Write(buf)

		// Get the buffer from this iteration.
		buf = hm.Sum(nil)
	}

	// Create hash with result.
	b64 := Base64Encode(buf)
	hash = []byte(fmt.Sprintf("%s%d$%s$", magic, iterations, salt))
	hash = append(hash, b64...)
	return
}

// Override the hash with salt function to encode PBKDF1 with SHA1 hash.
func (a *SHA1Crypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	iterations, err := strconv.ParseUint(a.Params, 10, 64)
	if err != nil {
		return nil, err
	}

	hash = a.Hash(password, salt, iterations)
	return
}

// Hash an password using default parameters with SHA1.
func HashSHA1Password(password []byte) (hash []byte, err error) {
	passwd := NewSHA1Passwd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with SHA1.
func HashSHA1PasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewSHA1Passwd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with SHA1.
func SHashSHA1Password(password string) (hash string, err error) {
	passwd := NewSHA1Passwd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with SHA1.
func SHashSHA1PasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewSHA1Passwd()
	hash, err = passwd.SHashPasswordWithSalt(salt, salt)
	if err != nil {
		return
	}
	return
}
