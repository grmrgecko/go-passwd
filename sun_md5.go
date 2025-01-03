package passwd

import (
	"crypto/md5"
	"fmt"
	"strconv"
)

type SunMD5 struct {
	Passwd
}

// Make an MD5Crypt password instance.
func NewSunMD5Passwd() PasswdInterface {
	m := new(SunMD5)
	m.Magic = SUN_MD5_MAGIC
	// Max of 8 characters in the salt per the spec.
	m.SaltLength = 8
	// Set the interface to allow parents to call overriden functions.
	m.i = m
	return m
}

/*
At each round of the algorithm, this string (including the trailing
NUL) may or may not be included in the input to MD5, depending on a
pseudorandom coin toss.  It is Hamlet's famous soliloquy from the
play of the same name, which is in the public domain.  Text from
<https://www.gutenberg.org/files/1524/old/2ws2610.tex> with double
blank lines replaced with `\n`.  Note that more recent Project
Gutenberg editions of _Hamlet_ are punctuated differently.
*/
const hamlet_quotation string = "To be, or not to be,--that is the question:--\n" +
	"Whether 'tis nobler in the mind to suffer\n" +
	"The slings and arrows of outrageous fortune\n" +
	"Or to take arms against a sea of troubles,\n" +
	"And by opposing end them?--To die,--to sleep,--\n" +
	"No more; and by a sleep to say we end\n" +
	"The heartache, and the thousand natural shocks\n" +
	"That flesh is heir to,--'tis a consummation\n" +
	"Devoutly to be wish'd. To die,--to sleep;--\n" +
	"To sleep! perchance to dream:--ay, there's the rub;\n" +
	"For in that sleep of death what dreams may come,\n" +
	"When we have shuffled off this mortal coil,\n" +
	"Must give us pause: there's the respect\n" +
	"That makes calamity of so long life;\n" +
	"For who would bear the whips and scorns of time,\n" +
	"The oppressor's wrong, the proud man's contumely,\n" +
	"The pangs of despis'd love, the law's delay,\n" +
	"The insolence of office, and the spurns\n" +
	"That patient merit of the unworthy takes,\n" +
	"When he himself might his quietus make\n" +
	"With a bare bodkin? who would these fardels bear,\n" +
	"To grunt and sweat under a weary life,\n" +
	"But that the dread of something after death,--\n" +
	"The undiscover'd country, from whose bourn\n" +
	"No traveller returns,--puzzles the will,\n" +
	"And makes us rather bear those ills we have\n" +
	"Than fly to others that we know not of?\n" +
	"Thus conscience does make cowards of us all;\n" +
	"And thus the native hue of resolution\n" +
	"Is sicklied o'er with the pale cast of thought;\n" +
	"And enterprises of great pith and moment,\n" +
	"With this regard, their currents turn awry,\n" +
	"And lose the name of action.--Soft you now!\n" +
	"The fair Ophelia!--Nymph, in thy orisons\n" +
	"Be all my sins remember'd.\n\000"

func (a *SunMD5) get_nth_bit(digest []byte, n uint64) uint {
	b := (n % 128) / 8
	bit := (n % 128) % 8
	output := digest[b] & (1 << bit)
	if output == 0 {
		return 0
	}
	return 1
}

func (s *SunMD5) MuffetCoinToss(digest []byte, iteration uint64) bool {
	var x, y, a, b, r, v, i uint = 0, 0, 0, 0, 0, 0, 0
	for ; i < 8; i++ {
		a = uint(digest[(i+0)%16])
		b = uint(digest[(i+3)%16])
		r = a >> (b % 5)
		v = uint(digest[r%16])
		if (b & (1 << (a % 8))) != 0 {
			v /= 2
		}
		x |= s.get_nth_bit(digest, uint64(v)) << i

		a = uint(digest[(i+8)%16])
		b = uint(digest[(i+11)%16])
		r = a >> (b % 5)
		v = uint(digest[r%16])
		if (b & (1 << (a % 8))) != 0 {
			v /= 2
		}
		y |= s.get_nth_bit(digest, uint64(v)) << i
	}

	if s.get_nth_bit(digest, iteration) == 1 {
		x /= 2
	}
	if s.get_nth_bit(digest, iteration+64) == 1 {
		y /= 2
	}

	output := s.get_nth_bit(digest, uint64(x)) ^ s.get_nth_bit(digest, uint64(y))
	return output != 0
}

// Hash a password with salt using MD5 crypt standard.
func (a *SunMD5) Hash(password []byte, salt []byte, additionalIterations uint64) (hash []byte) {
	// Salt should be a maximum of 8 characters.
	if len(salt) > 8 {
		salt = salt[0:8]
	}

	customIterations := false
	var iterations uint64 = 4096
	if additionalIterations != 0 {
		customIterations = true
		iterations += additionalIterations
	}

	quoteBytes := []byte(hamlet_quotation)

	output := fmt.Sprintf("%s$%s$", a.Magic, salt)
	if customIterations {
		output = fmt.Sprintf("%s,rounds=%d$%s$", a.Magic, additionalIterations, salt)
	}

	// Encode pass, salt, pass hash to feed into the next hash.
	h := md5.New()
	h.Write(password)
	h.Write([]byte(output))
	result := h.Sum(nil)

	// Perform iterations.
	var cnt uint64
	for cnt = 0; cnt < iterations; cnt++ {
		h.Reset()
		h.Write(result)

		if a.MuffetCoinToss(result, cnt) {
			h.Write(quoteBytes)
		}

		iterationS := strconv.FormatUint(cnt, 10)
		h.Write([]byte(iterationS))

		// Compute hash for next round.
		result = h.Sum(nil)
	}

	// Create hash with result.
	b64 := MD5Base64Encode(result)
	hash = []byte(output)
	hash = append(hash, '$')
	hash = append(hash, b64...)
	return
}

// Override the passwd hash with salt function to hash with Sun MD5.
func (a *SunMD5) HashPasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
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

// Hash an password using default parameters with Sun MD5.
func HashSunMD5Password(password []byte) (hash []byte, err error) {
	passwd := NewSunMD5Passwd()
	hash, err = passwd.HashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password with salt using default parameters with Sun MD5.
func HashSunMD5PasswordWithSalt(password []byte, salt []byte) (hash []byte, err error) {
	passwd := NewSunMD5Passwd()
	hash, err = passwd.HashPasswordWithSalt(password, salt)
	if err != nil {
		return
	}
	return
}

// Hash an password string using default parameters with Sun MD5.
func SHashSunMD5Password(password string) (hash string, err error) {
	passwd := NewSunMD5Passwd()
	hash, err = passwd.SHashPassword(password)
	if err != nil {
		return
	}
	return
}

// Hash an password string with salt using default parameters with Sun MD5.
func SHashSunMD5PasswordWithSalt(password string, salt string) (hash string, err error) {
	passwd := NewSunMD5Passwd()
	hash, err = passwd.SHashPasswordWithSalt(salt, salt)
	if err != nil {
		return
	}
	return
}
