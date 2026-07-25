package bootstrap

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"math/big"
	"strings"
	"time"
)

type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now().UTC()
}

type CryptoIDGenerator struct{}

func (CryptoIDGenerator) NewID(prefix string) (string, error) {
	var b [10]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
	return fmt.Sprintf("%s_%s", prefix, strings.ToLower(encoded)), nil
}

type CryptoCodeGenerator struct{}

func (CryptoCodeGenerator) NewCode(digits int) (string, error) {
	if digits <= 0 || digits > 12 {
		return "", fmt.Errorf("digits must be between 1 and 12")
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n.Int64()), nil
}
