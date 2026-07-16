package security

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	TOTPDigits = 6
	TOTPPeriod = 30
)

func NormalizeTOTPSecret(secret string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""), "-", ""))
}

func VerifyTOTP(secret, code string, now time.Time) bool {
	_, ok := verifyTOTPCounter(secret, code, now, 0, false)
	return ok
}

// VerifyTOTPAfter returns the matching counter only when it is newer than the
// last accepted counter. Persisting that counter prevents replay within the
// normal TOTP clock-skew window.
func VerifyTOTPAfter(secret, code string, now time.Time, lastAccepted uint64) (uint64, bool) {
	return verifyTOTPCounter(secret, code, now, lastAccepted, true)
}

func verifyTOTPCounter(secret, code string, now time.Time, lastAccepted uint64, enforceAfter bool) (uint64, bool) {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if len(code) != TOTPDigits {
		return 0, false
	}
	baseCounter := now.Unix() / TOTPPeriod
	for offset := -1; offset <= 1; offset++ {
		candidate := baseCounter + int64(offset)
		if candidate < 0 || (enforceAfter && uint64(candidate) <= lastAccepted) {
			continue
		}
		expected, ok := totpCodeForCounter(secret, uint64(candidate))
		if ok && hmac.Equal([]byte(expected), []byte(code)) {
			return uint64(candidate), true
		}
	}
	return 0, false
}

func TOTPCodeAt(secret string, now time.Time) (string, bool) {
	if now.Unix() < 0 {
		return "", false
	}
	return totpCodeForCounter(secret, uint64(now.Unix()/TOTPPeriod))
}

func totpCodeForCounter(secret string, counter uint64) (string, bool) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(NormalizeTOTPSecret(secret))
	if err != nil || len(key) == 0 {
		return "", false
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	modulo := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		modulo *= 10
	}
	return fmt.Sprintf("%0"+strconv.Itoa(TOTPDigits)+"d", value%modulo), true
}
