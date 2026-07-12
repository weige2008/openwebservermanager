package security

import (
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238SHA1Vector(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, ok := TOTPCodeAt(secret, time.Unix(59, 0).UTC())
	if !ok || code != "287082" {
		t.Fatalf("TOTPCodeAt() = %q, %v, want 287082, true", code, ok)
	}
}

func TestVerifyTOTPAcceptsNormalizedSecretAndAdjacentWindow(t *testing.T) {
	now := time.Unix(1234567890, 0).UTC()
	secret := "jbsw y3dp-ehpk3pxp"
	code, ok := TOTPCodeAt(secret, now.Add(-TOTPPeriod*time.Second))
	if !ok || !VerifyTOTP(secret, code, now) {
		t.Fatalf("VerifyTOTP rejected adjacent-window code %q", code)
	}
	if VerifyTOTP(secret, "12345", now) || VerifyTOTP("not-base32!", "123456", now) {
		t.Fatal("VerifyTOTP accepted malformed input")
	}
}
