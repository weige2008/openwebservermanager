package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"openwebservermanager/internal/model"
)

func TestMFAEnrollmentCannotOverwriteEnabledProfile(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	admin := rawPlatformUserByName(t, srv, "admin")
	secret := "JBSWY3DPEHPK3PXP"
	if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, secret, []string{"ABCDE-FGHIJ", "KLMNO-PQRST"}); err != nil {
		t.Fatalf("enable admin MFA: %v", err)
	}

	assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/setup", nil, adminCookie, http.StatusConflict)
	replacement := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/enable", map[string]any{
		"secret":   replacement,
		"mfa_code": totpCode(replacement, time.Now().UTC()),
	}, adminCookie, http.StatusConflict)

	profile, ok, err := srv.cfg.Store.UserMFAProfile(admin.ID)
	if err != nil || !ok {
		t.Fatalf("load retained MFA profile: ok=%v err=%v", ok, err)
	}
	if !profile.Enabled || profile.Secret != secret || profile.RecoveryCount != 2 {
		t.Fatalf("enabled MFA profile was overwritten: %#v", profile)
	}
}

func TestSameTOTPCompletesOnlyOneLoginChallenge(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	admin := rawPlatformUserByName(t, srv, "admin")
	secret := "JBSWY3DPEHPK3PXP"
	if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, secret, []string{"ABCDE-FGHIJ"}); err != nil {
		t.Fatalf("enable admin MFA: %v", err)
	}

	challengeToken := func() string {
		t.Helper()
		rec := assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin",
			"password": "password123",
		}, nil, http.StatusAccepted)
		var response map[string]any
		decodeResponse(t, rec, &response)
		token, _ := response["mfa_token"].(string)
		if token == "" {
			t.Fatalf("MFA challenge missing token: %v", response)
		}
		return token
	}

	firstToken := challengeToken()
	secondToken := challengeToken()
	code := totpCode(secret, time.Now().UTC())
	assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token": firstToken, "mfa_code": code,
	}, nil, http.StatusOK)
	second := assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token": secondToken, "mfa_code": code,
	}, nil, http.StatusUnauthorized)
	if !strings.Contains(second.Body.String(), "invalid MFA code") {
		t.Fatalf("replayed TOTP failure is unclear: %s", second.Body.String())
	}
}

func TestConcurrentMFARecoveryCodeConsumptionIsAtomic(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	admin := rawPlatformUserByName(t, srv, "admin")
	const recoveryCode = "ABCDE-FGHIJ"
	if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, "JBSWY3DPEHPK3PXP", []string{recoveryCode}); err != nil {
		t.Fatalf("enable admin MFA: %v", err)
	}

	const attempts = 24
	var wg sync.WaitGroup
	results := make(chan bool, attempts)
	errors := make(chan error, attempts)
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := srv.cfg.Store.ConsumeUserMFARecoveryCode(admin.ID, recoveryCode)
			results <- ok
			errors <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errors)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	for err := range errors {
		if err != nil {
			t.Fatalf("consume recovery code concurrently: %v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent recovery code successes = %d, want 1", successes)
	}
	profile, _, err := srv.cfg.Store.UserMFAProfile(admin.ID)
	if err != nil || profile.RecoveryCount != 0 {
		t.Fatalf("recovery code count after concurrent consumption = %d, err=%v", profile.RecoveryCount, err)
	}
}

func TestLoginPersistenceFailuresRestoreConsumedMFA(t *testing.T) {
	t.Run("auth session TOTP", func(t *testing.T) {
		srv, _ := newTestServer(t, nil)
		admin := rawPlatformUserByName(t, srv, "admin")
		secret := "JBSWY3DPEHPK3PXP"
		if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, secret, []string{"ABCDE-FGHIJ"}); err != nil {
			t.Fatalf("enable admin MFA: %v", err)
		}
		code := totpCode(secret, time.Now().UTC())
		removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "auth_sessions")
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "password123", "mfa_code": code,
		}, nil, http.StatusInternalServerError)
		removeBlocker()
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "password123", "mfa_code": code,
		}, nil, http.StatusOK)
	})

	t.Run("auth session recovery code", func(t *testing.T) {
		srv, _ := newTestServer(t, nil)
		admin := rawPlatformUserByName(t, srv, "admin")
		const recoveryCode = "ABCDE-FGHIJ"
		if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, "JBSWY3DPEHPK3PXP", []string{recoveryCode}); err != nil {
			t.Fatalf("enable admin MFA: %v", err)
		}
		removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "auth_sessions")
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "password123", "recovery_code": recoveryCode,
		}, nil, http.StatusInternalServerError)
		removeBlocker()
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "password123", "recovery_code": recoveryCode,
		}, nil, http.StatusOK)
	})

	t.Run("login failure reset", func(t *testing.T) {
		srv, _ := newTestServer(t, nil)
		admin := rawPlatformUserByName(t, srv, "admin")
		secret := "JBSWY3DPEHPK3PXP"
		if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, secret, []string{"ABCDE-FGHIJ"}); err != nil {
			t.Fatalf("enable admin MFA: %v", err)
		}
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "wrong-password",
		}, nil, http.StatusUnauthorized)
		code := totpCode(secret, time.Now().UTC())
		removeBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, loginFailureStateCollection, `"name":"login_failure_states"`)
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "password123", "mfa_code": code,
		}, nil, http.StatusInternalServerError)
		removeBlocker()
		assertStatus(t, srv, http.MethodPost, "/api/auth/login", map[string]any{
			"username": "admin", "password": "password123", "mfa_code": code,
		}, nil, http.StatusOK)
	})
}

func TestAccessMFAFailureRestoresConsumedCredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input accessMFAInput
	}{
		{name: "TOTP"},
		{name: "recovery code", input: accessMFAInput{MFACode: "ABCDE-FGHIJ"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, adminCookie := newTestServer(t, nil)
			admin := rawPlatformUserByName(t, srv, "admin")
			secret := "JBSWY3DPEHPK3PXP"
			if _, err := srv.cfg.Store.EnableUserMFA(admin.ID, secret, []string{"ABCDE-FGHIJ"}); err != nil {
				t.Fatalf("enable admin MFA: %v", err)
			}
			assertStatus(t, srv, http.MethodPost, "/api/admin/system-settings", map[string]any{
				"name": "Access MFA", "type": "access", "status": "enabled",
				"metadata": map[string]any{"access_mfa_enabled": true},
			}, adminCookie, http.StatusCreated)
			input := tc.input
			if tc.name == "TOTP" {
				input.MFACode = totpCode(secret, time.Now().UTC())
			}

			verify := func() (*httptest.ResponseRecorder, bool) {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, "/api/access/test/mfa", nil)
				req.AddCookie(adminCookie)
				rec := httptest.NewRecorder()
				return rec, srv.requireAccessMFA(rec, req, input)
			}
			removeBlocker := blockPlatformItemCreate(t, srv.cfg.Store, accessMFAGrantCollection)
			rec, allowed := verify()
			removeBlocker()
			if allowed || rec.Code != http.StatusInternalServerError {
				t.Fatalf("failed access grant allowed=%v status=%d body=%s", allowed, rec.Code, rec.Body.String())
			}
			_, allowed = verify()
			if !allowed {
				t.Fatal("MFA credential was not restored after access grant failure")
			}
		})
	}
}

func TestAccessMFAInputRejectsURLQuerySecrets(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/access/http/example/proxy/?mfa_code=123456&recovery_code=ABCDE-FGHIJ", nil)
	input := accessMFAInputFromRequest(req)
	if input.MFACode != "" || input.RecoveryCode != "" {
		t.Fatalf("URL query MFA secrets were accepted: %#v", input)
	}
	req.Header.Set("X-OpenWebServerManager-MFA-Code", " 654321 ")
	req.Header.Set("X-OpenWebServerManager-Recovery-Code", " KLMNO-PQRST ")
	input = accessMFAInputFromRequest(req)
	if input.MFACode != "654321" || input.RecoveryCode != "KLMNO-PQRST" {
		t.Fatalf("MFA headers were not parsed: %#v", input)
	}
}

func TestExternalAccountCanManageMFAWithoutLocalPassword(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	userRec := assertStatus(t, srv, http.MethodPost, "/api/admin/users", map[string]any{
		"name": "external-mfa-user", "type": "ldap", "status": "enabled",
		"metadata": map[string]any{"role": "user", "external_provider": "ldap"},
	}, adminCookie, http.StatusCreated)
	var item model.PlatformItem
	decodeResponse(t, userRec, &item)
	secret := "JBSWY3DPEHPK3PXP"
	if _, err := srv.cfg.Store.EnableUserMFA(item.ID, secret, []string{"ABCDE-FGHIJ", "KLMNO-PQRST"}); err != nil {
		t.Fatalf("enable external user MFA: %v", err)
	}
	user, ok, err := srv.authUserByID(item.ID)
	if err != nil || !ok {
		t.Fatalf("load external auth user: ok=%v err=%v", ok, err)
	}
	token, _, err := srv.auth.create(user)
	if err != nil {
		t.Fatalf("create external user session: %v", err)
	}
	userCookie := &http.Cookie{Name: authCookieName, Value: token}
	statusRec := assertStatus(t, srv, http.MethodGet, "/api/auth/mfa/status", nil, userCookie, http.StatusOK)
	if !strings.Contains(statusRec.Body.String(), `"password_required":false`) {
		t.Fatalf("external account incorrectly requires a local password: %s", statusRec.Body.String())
	}
	recoveryRec := assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/recovery-codes", map[string]any{
		"mfa_code": totpCode(secret, time.Now().UTC()),
	}, userCookie, http.StatusOK)
	var recoveryResponse map[string]any
	decodeResponse(t, recoveryRec, &recoveryResponse)
	recoveryCodes := stringSliceFromAny(recoveryResponse["recovery_codes"])
	if len(recoveryCodes) == 0 {
		t.Fatalf("external account recovery code regeneration returned none: %s", recoveryRec.Body.String())
	}
	assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/disable", map[string]any{
		"mfa_code": recoveryCodes[0],
	}, userCookie, http.StatusOK)
}

func TestPasskeyLoginHonorsForcedMFA(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	privateKey, credentialID, passkey := registerTestPasskeyWithCredentialID(t, srv, adminCookie, "admin", []byte("forced-mfa-passkey"))
	assertStatus(t, srv, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name": "Force MFA", "type": "security", "status": "enabled",
		"metadata": map[string]any{"force_mfa": true},
	}, adminCookie, http.StatusCreated)

	options := testPasskeyLoginOptions(t, srv, "admin")
	payload := testPasskeyAssertionPayload(t, options.ChallengeID, options.PublicKey.Challenge, options.PublicKey.RPID, credentialID, privateKey, 2, false)
	verifyRec := assertStatus(t, srv, http.MethodPost, "/api/auth/passkeys/login/verify", payload, nil, http.StatusAccepted)
	if len(verifyRec.Result().Cookies()) != 0 {
		t.Fatal("passkey bypassed forced MFA and issued a session")
	}
	var challenge map[string]any
	decodeResponse(t, verifyRec, &challenge)
	token, _ := challenge["mfa_token"].(string)
	secret, _ := challenge["secret"].(string)
	if token == "" || secret == "" || challenge["mfa_setup_required"] != true {
		t.Fatalf("forced passkey MFA challenge is incomplete: %v", challenge)
	}
	completeRec := assertStatus(t, srv, http.MethodPost, "/api/auth/mfa/complete-login", map[string]any{
		"token": token, "mfa_code": totpCode(secret, time.Now().UTC()),
	}, nil, http.StatusOK)
	if len(completeRec.Result().Cookies()) == 0 {
		t.Fatal("completed passkey MFA login did not issue a session")
	}
	logs := assertStatus(t, srv, http.MethodGet, "/api/admin/audit/login-logs", nil, adminCookie, http.StatusOK)
	for _, expected := range []string{`"type":"passkey"`, `"mfa_method":"totp_setup"`, passkey.ID} {
		if !strings.Contains(logs.Body.String(), expected) {
			t.Fatalf("passkey MFA login metadata missing %q: %s", expected, logs.Body.String())
		}
	}
}
