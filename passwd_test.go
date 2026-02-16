package passwd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckPassword(t *testing.T) {
	password := []byte("Test")

	tests := []struct {
		name string
		hash string
	}{
		{"sha1", "$sha1$245081$NabW/sfk3ZVVQc4BnZ/3$YoV1Iva6GK4tkxwahBmyH0TRCwBO"},
		{"sun md5", "$md5$lORrojKC$$RD9p64URLn3Wkv4Wa2xOW0"},
		{"sun md5 rounds", "$md5,rounds=53125$qrDebYUd$$3pJWS.a6VTC/cGehIfQb30"},
		{"md5", "$1$wuIXYcHV$1ufSGHoD0EkWPr75i52ST/"},
		{"nt", "$3$$4a1fab8f6b5441e0493dc7d41304bfb6"},
		{"sha256", "$5$AsETvlsIoaTP3w6G$OZY9mWRFXR9Pz0Xv1pS2TS/QCpxECLEG/dru/Y.nba/"},
		{"sha256 rounds", "$5$rounds=243006$oCvhLw/Nn9HuQIm4$VPKzWx9t.NHgmNpVHeSpzQ5y01z4BE14J.bvG8g2yi."},
		{"sha512", "$6$zt7D9I3Uu.EhrzEv$j50OCJ3oNdO2Ee7RE9XTDF7dhvrgRwc9NmjJUouk7czn4JTc/A6qLJIT1pMk7FUlTCYCLl6uBHm5NoEboAzIo0"},
		{"sha512 rounds", "$6$rounds=523044$.zMtRwbPP2sDg5a5$YgKUnqEda6wxkvDMbJoNjNBiFNpX7nP/uDFV3jV4ngmrXlFBua3n8oIi5St/Re8H3WOksLaody3eAhaGtAN0c/"},
		{"scrypt", "$7$CU..../....PpL3ULxY5DvYyvasS/a4a0$jqgg90svZLt5KQqFTwegHSn1pXU.aKDavZ3Eq8t2wx9"},
		{"yes crypt", "$y$j9T$G/uoZu1orhwOE/lUtohEa.$SMu/wxtyhBLa5xeRLVnznBx5vE0/VxY7rJZlQX27N84"},
		{"gost yes crypt", "$gy$j9T$etkZHzB483TIuw/58Df.N/$7DjHx/8jx.E/VLdyzMIIOJULHoZJ1PNlFl71KXaf0s7"},
		{"bcrypt", "$2a$14$QlFncTUDVo7aWRJvDicXzOyd8zipAj1c9vRlOw4no6XiBLHewlPH."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := CheckPassword([]byte(tc.hash), password)
			require.NoError(t, err)
			assert.True(t, res, "Password check failed for %s", tc.name)

			// Negative test: wrong password
			res, err = CheckPassword([]byte(tc.hash), []byte("WrongPass"))
			require.NoError(t, err)
			assert.False(t, res, "Password check should have failed for wrong password (%s)", tc.name)
		})
	}

	t.Run("InvalidHash", func(t *testing.T) {
		res, err := CheckPassword([]byte("$invalid$hash"), password)
		assert.Error(t, err)
		assert.False(t, res)
	})
}

func TestNewPasswordGeneration(t *testing.T) {
	password := []byte("Test")

	tests := []struct {
		name    string
		factory func() PasswdInterface
	}{
		{"sha1", NewSHA1Passwd},
		{"sun md5", NewSunMD5Passwd},
		{"sha256", NewSHA256CryptPasswd},
		{"sha512", NewSHA512CryptPasswd},
		{"scrypt", NewSCryptPasswd},
		{"yes crypt", NewYesCryptPasswd},
		{"gost yes crypt", NewGostYesCryptPasswd},
		{"bcrypt", NewBCryptPasswd},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			passwd := tc.factory()
			hash, err := passwd.HashPassword(password)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)

			res, err := CheckPassword(hash, password)
			require.NoError(t, err)
			assert.True(t, res, "Re-hash check failed for %s", tc.name)

			t.Logf("%s: %s", tc.name, string(hash))
		})
	}
}

func TestFollowStandards(t *testing.T) {
	t.Run("DefaultIsDisabled", func(t *testing.T) {
		p := NewSHA512CryptPasswd().(*SHA512Crypt)
		p.SetParams("rounds=999")

		hash, err := p.SHashPasswordWithSalt("Test", "salt")
		require.NoError(t, err)
		assert.Contains(t, hash, "$6$rounds=999$salt$")
		assert.False(t, p.FollowStandards)
	})

	t.Run("SHA512RoundsRejected", func(t *testing.T) {
		p := NewSHA512CryptPasswd().(*SHA512Crypt)
		p.SetParams("rounds=999")
		p.FollowStandards = true

		_, err := p.SHashPasswordWithSalt("Test", "salt")
		require.Error(t, err)
	})

	t.Run("BCryptCostRejected", func(t *testing.T) {
		p := NewBCryptPasswd().(*BCrypt)
		p.SetParams("b$03")
		p.FollowStandards = true

		_, err := p.SHashPasswordWithSalt("Test", "abcdefghijklmnopqrstuu")
		require.Error(t, err)
	})

	t.Run("SCryptNRejected", func(t *testing.T) {
		p := NewSCryptPasswd().(*SCrypt)
		require.NoError(t, p.SetSCryptParams(1, 1, 1))
		p.FollowStandards = true

		_, err := p.SHashPasswordWithSalt("Test", "abcdefghijklmnopqrstuv")
		require.Error(t, err)
	})
}
