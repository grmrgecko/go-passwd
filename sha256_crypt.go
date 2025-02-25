package passwd

import (
	"crypto/sha256"
	"fmt"
)

type SHA256Crypt struct {
	Passwd
}

// Make an MD5Crypt password instance.
func NewSHA256CryptPasswd() PasswdInterface {
	m := new(SHA256Crypt)
	m.Magic = SHA256_CRYPT_MAGIC
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

// Hash a password with salt using SHA256 crypt standard.
func (a *SHA256Crypt) Hash(password []byte, salt []byte, iterations uint64) (hash []byte) {
	// Salt should be a maximum of 16 characters.
	if len(salt) > 16 {
		salt = salt[0:16]
	}

	passwordLen := len(password)
	saltLen := len(salt)

	customIterations := true
	if iterations == 0 {
		customIterations = false
		iterations = 5000
	}

	// Encode pass, salt, pass hash to feed into the next hash.
	h := sha256.New()
	h.Write(password)
	h.Write(salt)
	h.Write(password)
	result := h.Sum(nil)

	// Encod the password and salt, and recycle bytes from prior hash.
	h.Reset()
	h.Write(password)
	h.Write(salt)

	// Append characters from the prior encode until it equals the length of the password.
	HashBlockRecycle(h, result, passwordLen)

	// Alternate the prior encode with the password for the binary length of the password.
	var cnt uint64
	for cnt = uint64(passwordLen); cnt > 0; cnt >>= 1 {
		if cnt&1 != 0 {
			h.Write(result)
		} else {
			h.Write(password)
		}
	}

	// Calculate sum for iterations.
	result = h.Sum(nil)

	// Calculate a hash of password added for each character of the password for recycling in iterations.
	h.Reset()
	for cnt = 0; cnt < uint64(passwordLen); cnt++ {
		h.Write(password)
	}
	p_bytes := h.Sum(nil)

	// For maximum salt size plus the integer representation of the first byte of the prior hash,
	// write the entire salt to the hash for recycling in iterations.
	h.Reset()
	for cnt = 0; cnt < 16+uint64(result[0]); cnt++ {
		h.Write(salt)
	}
	s_bytes := h.Sum(nil)

	// For the defined number of interations, hash using bytes from
	// the above password and salt hashes and prior hash iteration.
	for cnt = 0; cnt < iterations; cnt++ {
		h.Reset()

		// Add pass or prior result depending on bit of current iteration.
		if cnt&1 != 0 {
			HashBlockRecycle(h, p_bytes, passwordLen)
		} else {
			h.Write(result)
		}

		// Add salt for numbers not divisible by 3.
		if cnt%3 != 0 {
			HashBlockRecycle(h, s_bytes, saltLen)
		}

		// Add password for numbers not divisible by 7.
		if cnt%7 != 0 {
			HashBlockRecycle(h, p_bytes, passwordLen)
		}

		// Add the reverse of the above pass or prior result.
		// This ensures we at a minimum have both the password,
		// and the prior result in the hash calculation for the round.
		if cnt&1 != 0 {
			h.Write(result)
		} else {
			HashBlockRecycle(h, p_bytes, passwordLen)
		}

		// Compute hash for next round.
		result = h.Sum(nil)
	}

	output := fmt.Sprintf("%s%s$", a.Magic, salt)
	if customIterations {
		output = fmt.Sprintf("%srounds=%d$%s$", a.Magic, iterations, salt)
	}

	// Create hash with result.
	b64 := Base64RotateEncode(result, false)
	hash = []byte(output)
	hash = append(hash, b64...)
	return
}

// Override the passwd hash with salt function to hash with SHA256 crypt.
func (a *SHA256Crypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	// Parse iterations from parameter.
	var iterations uint64
	if a.Params != "" {
		_, err = fmt.Sscanf(a.Params, "rounds=%d", &iterations)
		if err != nil {
			return
		}
	}

	// Compute hash.
	hash = a.Hash(password, salt, iterations)
	return
}

// Hash an password using default parameters with SHA256.
func HashSHA256Password(password []byte) (hash []byte, err error) {
	passwd := NewSHA256CryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with SHA256.
func HashSHA256PasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewSHA256CryptPasswd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with SHA256.
func SHashSHA256Password(password string) (hash string, err error) {
	passwd := NewSHA256CryptPasswd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with SHA256.
func SHashSHA256PasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewSHA256CryptPasswd()
	hash, err = passwd.SHashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}
