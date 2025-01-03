package passwd

import "crypto/md5"

type MD5Crypt struct {
	Passwd
}

// Make an MD5Crypt password instance.
func NewMD5CryptPasswd() PasswdInterface {
	m := new(MD5Crypt)
	m.Magic = MD5_CRYPT_MAGIC
	// Max of 8 characters in the salt per the spec.
	m.SaltLength = 8
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

// Hash a password with salt using MD5 crypt standard.
func (a *MD5Crypt) Hash(password []byte, salt []byte) (hash []byte) {
	magic := []byte(a.Magic)

	// Salt should be a maximum of 8 characters.
	if len(salt) > 8 {
		salt = salt[0:8]
	}

	// Encode pass, salt, pass hash to feed into the next hash.
	h := md5.New()
	h.Write(password)
	h.Write(salt)
	h.Write(password)
	result := h.Sum(nil)

	// Encode pass, magic, salt, and some extra stuff to help limit brute force attacks.
	h.Reset()
	h.Write(password)
	h.Write(magic)
	h.Write(salt)

	// Append characters from the prior encode until it equals the length of the password.
	HashBlockRecycle(h, result, len(password))

	// For compatibility: Every 1 bit of the password length, append null.
	// Every 0 bit of the password length, append the first character of the
	// password. Yes, this is a weird thing. But think, weird thing equals
	// harder for brute forcers.
	result = []byte{'\000'}
	var cnt int
	for cnt = len(password); cnt > 0; cnt >>= 1 {
		if cnt&1 != 0 {
			h.Write(result[:1])
		} else {
			h.Write(password[:1])
		}
	}

	// Compute the hash to feed into the 1000 iterations.
	result = h.Sum(nil)

	// For 1000 iterations, make a new hash feeding the prior hash,
	// password, and salt at different points. This is designed to
	// limit brute force attempts, although todays tech is fast.
	for cnt = 0; cnt < 1000; cnt++ {
		h.Reset()

		// Add pass or prior result depending on bit of current iteration.
		if cnt&1 != 0 {
			h.Write(password)
		} else {
			h.Write(result)
		}

		// Add salt for numbers not divisible by 3.
		if cnt%3 != 0 {
			h.Write(salt)
		}

		// Add password for numbers not divisible by 7.
		if cnt%7 != 0 {
			h.Write(password)
		}

		// Add the reverse of the above pass or prior result.
		// This ensures we at a minimum have both the password,
		// and the prior result in the hash calculation for the round.
		if cnt&1 != 0 {
			h.Write(result)
		} else {
			h.Write(password)
		}

		// Compute hash for next round.
		result = h.Sum(nil)
	}

	// Create hash with result.
	b64 := MD5Base64Encode(result)
	hash = append(magic, salt...)
	hash = append(hash, '$')
	hash = append(hash, b64...)
	return
}

// Override the passwd hash with salt function to hash with MD5 crypt.
func (a *MD5Crypt) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	hash = a.Hash(password, salt)
	return
}

// Hash an password using default parameters with MD5.
func HashMD5Password(password []byte) (hash []byte, err error) {
	passwd := NewMD5CryptPasswd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with MD5.
func HashMD5PasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewMD5CryptPasswd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with MD5.
func SHashMD5Password(password string) (hash string, err error) {
	passwd := NewMD5CryptPasswd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with MD5.
func SHashMD5PasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewMD5CryptPasswd()
	hash, err = passwd.SHashPasswordWithSalt(salt, salt)
	if err != nil {
		return
	}
	return
}
