package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"net/http"
	"strings"
	"testing"

	"openwebservermanager/internal/model"
)

func TestPasskeyRejectsMalformedCredentialEnvelopes(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	privateKey, credentialID, _ := registerTestPasskeyWithCredentialID(t, handler, adminCookie, "admin", []byte("strict-passkey-credential"))

	t.Run("registration requires public key type", func(t *testing.T) {
		optionsRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, adminCookie, http.StatusOK)
		var options testPasskeyCreationOptionsResponse
		decodeResponse(t, optionsRec, &options)
		payload := testPasskeyRegistrationPayload(t, options, "admin", []byte("missing-type-registration"), privateKey)
		payload["type"] = ""
		assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", payload, adminCookie, http.StatusBadRequest)
	})

	t.Run("login requires public key type", func(t *testing.T) {
		options := testPasskeyLoginOptions(t, handler, "admin")
		payload := testPasskeyAssertionPayload(t, options.ChallengeID, options.PublicKey.Challenge, options.PublicKey.RPID, credentialID, privateKey, 2, false)
		payload["type"] = ""
		rec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", payload, nil, http.StatusUnauthorized)
		if !strings.Contains(rec.Body.String(), "credential type") {
			t.Fatalf("missing credential type rejection = %s", rec.Body.String())
		}
	})

	t.Run("credential id must match raw id", func(t *testing.T) {
		options := testPasskeyLoginOptions(t, handler, "admin")
		payload := testPasskeyAssertionPayload(t, options.ChallengeID, options.PublicKey.Challenge, options.PublicKey.RPID, credentialID, privateKey, 2, false)
		payload["id"] = passkeyBase64Encode([]byte("different-credential"))
		rec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", payload, nil, http.StatusUnauthorized)
		if !strings.Contains(rec.Body.String(), "does not match raw id") {
			t.Fatalf("credential id mismatch rejection = %s", rec.Body.String())
		}
	})

	t.Run("oversized client data is rejected", func(t *testing.T) {
		options := testPasskeyLoginOptions(t, handler, "admin")
		payload := testPasskeyAssertionPayload(t, options.ChallengeID, options.PublicKey.Challenge, options.PublicKey.RPID, credentialID, privateKey, 2, false)
		payload["response"].(map[string]any)["client_data_json"] = passkeyBase64Encode(make([]byte, maxPasskeyClientDataBytes+1))
		rec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", payload, nil, http.StatusUnauthorized)
		if !strings.Contains(rec.Body.String(), "client data is too large") {
			t.Fatalf("oversized client data rejection = %s", rec.Body.String())
		}
	})
}

func TestPasskeySignCounterRejectsResetButAllowsCounterlessAuthenticators(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	privateKey, credentialID, passkey := registerTestPasskeyWithCredentialID(t, handler, adminCookie, "admin", []byte("counter-passkey-credential"))

	resetOptions := testPasskeyLoginOptions(t, handler, "admin")
	resetPayload := testPasskeyAssertionPayload(t, resetOptions.ChallengeID, resetOptions.PublicKey.Challenge, resetOptions.PublicKey.RPID, credentialID, privateKey, 0, false)
	resetRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", resetPayload, nil, http.StatusUnauthorized)
	if !strings.Contains(resetRec.Body.String(), "sign count did not advance") {
		t.Fatalf("reset sign counter rejection = %s", resetRec.Body.String())
	}

	raw, ok, err := srv.cfg.Store.GetPlatformItem("passkeys", passkey.ID)
	if err != nil || !ok {
		t.Fatalf("load passkey: ok=%v err=%v", ok, err)
	}
	raw.Metadata["sign_count"] = 0
	if _, err := srv.cfg.Store.SavePlatformItem("passkeys", raw); err != nil {
		t.Fatalf("reset stored counter for counterless authenticator: %v", err)
	}

	counterlessOptions := testPasskeyLoginOptions(t, handler, "admin")
	counterlessPayload := testPasskeyAssertionPayload(t, counterlessOptions.ChallengeID, counterlessOptions.PublicKey.Challenge, counterlessOptions.PublicKey.RPID, credentialID, privateKey, 0, false)
	assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/login/verify", counterlessPayload, nil, http.StatusOK)
}

func TestPasskeyRegistrationNameAndCountLimits(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)

	optionsRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, adminCookie, http.StatusOK)
	var options testPasskeyCreationOptionsResponse
	decodeResponse(t, optionsRec, &options)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	longNamePayload := testPasskeyRegistrationPayload(t, options, "admin", []byte("long-name-passkey"), privateKey)
	longNamePayload["name"] = strings.Repeat("a", maxPasskeyNameRunes+1)
	nameRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/verify", longNamePayload, adminCookie, http.StatusBadRequest)
	if !strings.Contains(nameRec.Body.String(), "passkey name") {
		t.Fatalf("long passkey name rejection = %s", nameRec.Body.String())
	}

	userIDRaw, err := passkeyBase64Decode(options.PublicKey.User.ID)
	if err != nil {
		t.Fatalf("decode passkey user id: %v", err)
	}
	for index := 0; index < maxPasskeysPerUser; index++ {
		if _, err := srv.cfg.Store.CreatePlatformItem("passkeys", model.PlatformItemRequest{
			Name:    "limit passkey",
			Type:    "public-key",
			Status:  "enabled",
			OwnerID: string(userIDRaw),
			Metadata: map[string]any{
				"credential_id": passkeyBase64Encode([]byte{byte(index + 1)}),
			},
		}); err != nil {
			t.Fatalf("create passkey %d for limit test: %v", index, err)
		}
	}
	limitRec := assertStatus(t, handler, http.MethodPost, "/api/auth/passkeys/register/options", map[string]any{}, adminCookie, http.StatusConflict)
	if !strings.Contains(limitRec.Body.String(), "at most 20") {
		t.Fatalf("passkey limit rejection = %s", limitRec.Body.String())
	}
}

func TestPasskeyBackupStateAndNameValidation(t *testing.T) {
	authData := make([]byte, 37)
	rpHash := sha256.Sum256(nil)
	copy(authData, rpHash[:])
	authData[32] = 0x01 | 0x04 | 0x10
	if _, err := validatePasskeyAssertionAuthData(authData, ""); err == nil || !strings.Contains(err.Error(), "backup state") {
		t.Fatalf("invalid passkey backup state was accepted: %v", err)
	}
	if _, err := normalizePasskeyName("bad\x00name", "fallback"); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("control character passkey name was accepted: %v", err)
	}
}
