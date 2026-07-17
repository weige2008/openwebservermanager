package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"openwebservermanager/internal/model"
)

func TestOIDCClientConfigurationValidation(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	srv := handler.(*Server)
	create := func(name, clientType, method, redirect string, scopes []string, secret string, want int) *httptest.ResponseRecorder {
		t.Helper()
		metadata := map[string]any{
			"client_id":     name,
			"redirect_uris": []string{redirect},
			"scopes":        scopes,
		}
		if method != "" {
			metadata["token_endpoint_auth_method"] = method
		}
		return assertStatus(t, handler, http.MethodPost, "/api/admin/oidc-clients", map[string]any{
			"name": name, "type": clientType, "status": "enabled", "password": secret, "metadata": metadata,
		}, adminCookie, want)
	}

	create("valid-basic", "confidential", "client_secret_basic", "https://client.example/callback", []string{"openid", "profile"}, "basic-secret", http.StatusCreated)
	postRec := create("valid-post", "confidential", "client_secret_post", "http://127.0.0.1:18080/callback", []string{"openid", "email"}, "post-secret", http.StatusCreated)
	var postClient model.PlatformItem
	decodeResponse(t, postRec, &postClient)
	create("valid-native", "public", "none", "com.example.native:/oauth2redirect", []string{"openid", "profile"}, "", http.StatusCreated)
	create("unconfigured-confidential", "confidential", "client_secret_basic", "https://client.example/unconfigured", []string{"openid"}, "", http.StatusCreated)
	assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {"unconfigured-confidential"}, "redirect_uri": {"https://client.example/unconfigured"}, "scope": {"openid"},
	}.Encode(), nil, adminCookie, http.StatusBadRequest)

	duplicate := create("valid-basic", "confidential", "client_secret_basic", "https://other.example/callback", []string{"openid"}, "another-secret", http.StatusBadRequest)
	if !strings.Contains(duplicate.Body.String(), "already in use") {
		t.Fatalf("duplicate client_id error is unclear: %s", duplicate.Body.String())
	}
	duplicateUpdate := assertStatus(t, handler, http.MethodPatch, "/api/admin/oidc-clients/"+postClient.ID, map[string]any{
		"metadata": map[string]any{
			"client_id": "valid-basic", "redirect_uris": []string{"http://127.0.0.1:18080/callback"},
			"scopes": []string{"openid", "email"}, "token_endpoint_auth_method": "client_secret_post",
		},
	}, adminCookie, http.StatusBadRequest)
	if !strings.Contains(duplicateUpdate.Body.String(), "already in use") {
		t.Fatalf("duplicate client_id update error is unclear: %s", duplicateUpdate.Body.String())
	}
	postAfter, ok, err := srv.cfg.Store.GetPlatformItem("oidc_clients", postClient.ID)
	if err != nil || !ok || oidcClientID(postAfter) != "valid-post" {
		t.Fatalf("rejected duplicate update changed client: ok=%v err=%v item=%#v", ok, err, postAfter)
	}
	for _, tc := range []struct {
		name, clientType, method, redirect string
		scopes                             []string
	}{
		{name: "remote-http", clientType: "confidential", method: "client_secret_basic", redirect: "http://client.example/callback", scopes: []string{"openid"}},
		{name: "fragment", clientType: "confidential", method: "client_secret_basic", redirect: "https://client.example/callback#fragment", scopes: []string{"openid"}},
		{name: "userinfo", clientType: "confidential", method: "client_secret_basic", redirect: "https://user:pass@client.example/callback", scopes: []string{"openid"}},
		{name: "redirect-whitespace", clientType: "confidential", method: "client_secret_basic", redirect: " https://client.example/callback", scopes: []string{"openid"}},
		{name: "confidential-none", clientType: "confidential", method: "none", redirect: "https://client.example/callback", scopes: []string{"openid"}},
		{name: "public-basic", clientType: "public", method: "client_secret_basic", redirect: "https://client.example/callback", scopes: []string{"openid"}},
		{name: "missing-openid", clientType: "confidential", method: "client_secret_basic", redirect: "https://client.example/callback", scopes: []string{"profile"}},
		{name: "duplicate-scope", clientType: "confidential", method: "client_secret_basic", redirect: "https://client.example/callback", scopes: []string{"openid", "openid"}},
		{name: "missing-scopes", clientType: "confidential", method: "client_secret_basic", redirect: "https://client.example/callback", scopes: []string{}},
		{name: "client id whitespace", clientType: "confidential", method: "client_secret_basic", redirect: "https://client.example/callback", scopes: []string{"openid"}},
		{name: "confidential-custom-scheme", clientType: "confidential", method: "client_secret_basic", redirect: "com.example.app:/callback", scopes: []string{"openid"}},
		{name: "javascript-scheme", clientType: "public", method: "none", redirect: "javascript:alert(1)", scopes: []string{"openid"}},
		{name: "data-scheme", clientType: "public", method: "none", redirect: "data:text/html,callback", scopes: []string{"openid"}},
		{name: "single-label-scheme", clientType: "public", method: "none", redirect: "native:/callback", scopes: []string{"openid"}},
		{name: "private-scheme-host", clientType: "public", method: "none", redirect: "com.example.app://callback.example/path", scopes: []string{"openid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := ""
			if tc.clientType == "confidential" {
				secret = "client-secret"
			}
			create(tc.name, tc.clientType, tc.method, tc.redirect, tc.scopes, secret, http.StatusBadRequest)
		})
	}

	if _, err := srv.cfg.Store.SavePlatformItem("oidc_clients", model.PlatformItem{
		ID: "legacy-invalid-client", Name: "legacy-invalid", Type: "public", Status: "enabled",
		Metadata: map[string]any{
			"client_id": "legacy-invalid", "redirect_uris": []string{"http://remote.example/callback"},
			"scopes": []string{"openid"}, "token_endpoint_auth_method": "none",
		},
	}); err != nil {
		t.Fatal(err)
	}
	assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+url.Values{
		"response_type": {"code"}, "client_id": {"legacy-invalid"}, "redirect_uri": {"http://remote.example/callback"}, "scope": {"openid"},
	}.Encode(), nil, adminCookie, http.StatusBadRequest)
}

func TestOIDCTokenClientAuthenticationAndScopedClaims(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	client := createOIDCHardeningClient(t, handler, adminCookie, "post-client", "confidential", "client_secret_post", "https://client.example/post", []string{"openid", "profile", "email"}, "post-secret")
	_ = client
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name": "oidc-scope-user", "type": "local", "status": "enabled", "password": "password123",
		"metadata": map[string]any{"role": "user", "email": "scope-user@example.test"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{
		"username": "oidc-scope-user", "password": "password123",
	}, nil, http.StatusOK)
	userCookie := loginRec.Result().Cookies()[0]

	code := issueOIDCHardeningCode(t, handler, userCookie, "post-client", "https://client.example/post", "openid email", "", "")
	wrongBasic := performOIDCTokenRequest(handler, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/post"},
	}, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("post-client:post-secret"))})
	if wrongBasic.Code != http.StatusUnauthorized || !strings.Contains(wrongBasic.Body.String(), `"error":"invalid_client"`) {
		t.Fatalf("post client accepted Basic authentication: status=%d body=%s", wrongBasic.Code, wrongBasic.Body.String())
	}
	if wrongBasic.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("post client advertised Basic after method mismatch: %q", wrongBasic.Header().Get("WWW-Authenticate"))
	}

	tokenRec := performOIDCTokenRequest(handler, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"post-client"}, "client_secret": {"post-secret"},
		"code": {code}, "redirect_uri": {"https://client.example/post"},
	}, nil)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("post client token exchange failed: status=%d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	if tokenRec.Header().Get("Cache-Control") != "no-store" || tokenRec.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("token response cache headers = %q, %q", tokenRec.Header().Get("Cache-Control"), tokenRec.Header().Get("Pragma"))
	}
	var tokenPayload map[string]any
	decodeResponse(t, tokenRec, &tokenPayload)
	accessToken, _ := tokenPayload["access_token"].(string)
	idToken, _ := tokenPayload["id_token"].(string)
	claims := decodeOIDCTestJWTClaims(t, idToken)
	if claims["email"] != "scope-user@example.test" || claims["name"] != nil || claims["role"] != nil {
		t.Fatalf("ID token did not honor requested scopes: %#v", claims)
	}
	userinfo := assertStatusWithHeaders(t, handler, http.MethodGet, "/api/oidc/userinfo", nil, nil, map[string]string{
		"Authorization": "Bearer " + accessToken,
	}, http.StatusOK)
	var userinfoClaims map[string]any
	decodeResponse(t, userinfo, &userinfoClaims)
	if userinfoClaims["sub"] != user.ID || userinfoClaims["email"] != "scope-user@example.test" || userinfoClaims["name"] != nil || userinfoClaims["role"] != nil {
		t.Fatalf("userinfo did not honor requested scopes: %#v", userinfoClaims)
	}
	if userinfo.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("userinfo cache control = %q", userinfo.Header().Get("Cache-Control"))
	}

	mixed := performOIDCTokenRequest(handler, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"post-client"}, "client_secret": {"post-secret"}, "code": {"unused"},
	}, map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("post-client:post-secret"))})
	if mixed.Code != http.StatusUnauthorized || !strings.Contains(mixed.Body.String(), "multiple client authentication") {
		t.Fatalf("mixed client authentication was not rejected: status=%d body=%s", mixed.Code, mixed.Body.String())
	}
	duplicate := performOIDCTokenRequest(handler, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"post-client"}, "client_secret": {"one", "two"}, "code": {"unused"},
	}, nil)
	if duplicate.Code != http.StatusBadRequest || !strings.Contains(duplicate.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("duplicate token parameter was not rejected: status=%d body=%s", duplicate.Code, duplicate.Body.String())
	}

	createOIDCHardeningClient(t, handler, adminCookie, "opaque-secret-client", "confidential", "client_secret_basic", "https://client.example/opaque", []string{"openid"}, " secret-with-spaces ")
	opaqueCode := issueOIDCHardeningCode(t, handler, adminCookie, "opaque-secret-client", "https://client.example/opaque", "openid", "", "")
	opaqueForm := url.Values{"grant_type": {"authorization_code"}, "code": {opaqueCode}, "redirect_uri": {"https://client.example/opaque"}}
	trimmedSecret := performOIDCTokenRequest(handler, opaqueForm, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("opaque-secret-client:secret-with-spaces")),
	})
	if trimmedSecret.Code != http.StatusUnauthorized {
		t.Fatalf("OIDC client secret whitespace was normalized: status=%d body=%s", trimmedSecret.Code, trimmedSecret.Body.String())
	}
	exactSecret := performOIDCTokenRequest(handler, opaqueForm, map[string]string{
		"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("opaque-secret-client: secret-with-spaces ")),
	})
	if exactSecret.Code != http.StatusOK {
		t.Fatalf("exact opaque OIDC client secret failed: status=%d body=%s", exactSecret.Code, exactSecret.Body.String())
	}
}

func TestOIDCAuthorizeRejectsParameterPollutionAndPKCEDowngrade(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	createOIDCHardeningClient(t, handler, adminCookie, "public-client", "public", "none", "https://client.example/public", []string{"openid", "profile"}, "")
	redirectURI := "https://client.example/public"
	plainVerifier := strings.Repeat("a", 43)
	plain := url.Values{
		"response_type": {"code"}, "client_id": {"public-client"}, "redirect_uri": {redirectURI},
		"scope": {"openid"}, "state": {"plain-state"}, "code_challenge": {plainVerifier}, "code_challenge_method": {"plain"},
	}
	plainRec := assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+plain.Encode(), nil, adminCookie, http.StatusFound)
	plainLocation, _ := url.Parse(plainRec.Header().Get("Location"))
	if plainLocation.Query().Get("error") != "invalid_request" || !strings.Contains(plainLocation.Query().Get("error_description"), "S256") {
		t.Fatalf("public plain PKCE was not rejected: %s", plainLocation.String())
	}

	duplicateClient := cloneURLValues(plain)
	duplicateClient["client_id"] = []string{"public-client", "other-client"}
	assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+duplicateClient.Encode(), nil, adminCookie, http.StatusBadRequest)

	duplicateState := cloneURLValues(plain)
	duplicateState.Set("code_challenge_method", "S256")
	challenge := sha256.Sum256([]byte(plainVerifier))
	duplicateState.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	duplicateState["state"] = []string{"one", "two"}
	duplicateStateRec := assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+duplicateState.Encode(), nil, adminCookie, http.StatusFound)
	duplicateStateLocation, _ := url.Parse(duplicateStateRec.Header().Get("Location"))
	if duplicateStateLocation.Query().Get("error") != "invalid_request" || duplicateStateLocation.Query().Has("state") {
		t.Fatalf("duplicated state was reflected or accepted: %s", duplicateStateLocation.String())
	}

	oversizedState := cloneURLValues(duplicateState)
	oversizedState.Set("state", strings.Repeat("s", 2049))
	oversizedRec := assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+oversizedState.Encode(), nil, adminCookie, http.StatusFound)
	oversizedLocation, _ := url.Parse(oversizedRec.Header().Get("Location"))
	if oversizedLocation.Query().Get("error") != "invalid_request" || oversizedLocation.Query().Has("state") {
		t.Fatalf("oversized state was reflected or accepted: %s", oversizedLocation.String())
	}
}

func TestOIDCTokenMutationRollbackAndConcurrentCodeUse(t *testing.T) {
	srv, adminCookie := newTestServer(t, nil)
	handler := http.Handler(srv)
	createOIDCHardeningClient(t, handler, adminCookie, "rollback-client", "public", "none", "https://client.example/rollback", []string{"openid", "profile"}, "")
	verifier := "rollback-verifier-1234567890-abcdefghijklmnop"
	challenge := sha256.Sum256([]byte(verifier))
	challengeValue := base64.RawURLEncoding.EncodeToString(challenge[:])
	issue := func() string {
		t.Helper()
		return issueOIDCHardeningCode(t, handler, adminCookie, "rollback-client", "https://client.example/rollback", "openid profile", challengeValue, "S256")
	}
	exchange := func(code string) *httptest.ResponseRecorder {
		return performOIDCTokenRequest(handler, url.Values{
			"grant_type": {"authorization_code"}, "client_id": {"rollback-client"}, "code": {code},
			"redirect_uri": {"https://client.example/rollback"}, "code_verifier": {verifier},
		}, nil)
	}

	code := issue()
	removeAccessBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "oidc_access_tokens")
	failed := exchange(code)
	removeAccessBlocker()
	if failed.Code != http.StatusInternalServerError || !strings.Contains(failed.Body.String(), `"error":"server_error"`) {
		t.Fatalf("access token persistence failure was not reported: status=%d body=%s", failed.Code, failed.Body.String())
	}
	logs, err := srv.cfg.Store.ListPlatformItems("operation_logs")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range logs {
		if item.Name == "oidc.token" {
			t.Fatalf("failed access token creation wrote a success operation log: %#v", item)
		}
	}
	if retry := exchange(code); retry.Code != http.StatusOK {
		t.Fatalf("authorization code was not restored after access token failure: status=%d body=%s", retry.Code, retry.Body.String())
	}

	concurrentCode := issue()
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- exchange(concurrentCode).Code
		}()
	}
	wg.Wait()
	close(results)
	counts := map[int]int{}
	for status := range results {
		counts[status]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusBadRequest] != 1 {
		t.Fatalf("concurrent authorization code results = %v, want one 200 and one 400", counts)
	}

	logFailureCode := issue()
	accessBefore, _ := srv.cfg.Store.ListPlatformItems("oidc_access_tokens")
	removeLogBlocker := blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	logFailure := exchange(logFailureCode)
	removeLogBlocker()
	if logFailure.Code != http.StatusInternalServerError {
		t.Fatalf("operation log failure status=%d body=%s", logFailure.Code, logFailure.Body.String())
	}
	accessAfter, _ := srv.cfg.Store.ListPlatformItems("oidc_access_tokens")
	if len(accessAfter) != len(accessBefore) {
		t.Fatalf("operation log failure retained access token: before=%d after=%d", len(accessBefore), len(accessAfter))
	}
	if retry := exchange(logFailureCode); retry.Code != http.StatusOK {
		t.Fatalf("operation log failure did not restore code: status=%d body=%s", retry.Code, retry.Body.String())
	}

	rollbackFailureCode := issue()
	removeLogBlocker = blockPlatformItemCreate(t, srv.cfg.Store, "operation_logs")
	removeDeleteBlocker := blockPlatformItemDeletePayloadFragment(t, srv.cfg.Store, "oidc_access_tokens", `"name":"oidc_access_tokens"`)
	rollbackFailure := exchange(rollbackFailureCode)
	removeDeleteBlocker()
	removeLogBlocker()
	if rollbackFailure.Code != http.StatusInternalServerError || !strings.Contains(rollbackFailure.Body.String(), "failed to roll back OIDC token issuance") {
		t.Fatalf("OIDC rollback failure was not reported: status=%d body=%s", rollbackFailure.Code, rollbackFailure.Body.String())
	}
	if !coreAuditLogsContainAction(srv.cfg.Store, "oidc.token.restore_failed") {
		t.Fatal("OIDC rollback failure was not written to core audit logs")
	}
}

func TestOIDCTokenRejectsCodeForDisabledUser(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	createOIDCHardeningClient(t, handler, adminCookie, "disabled-user-client", "confidential", "client_secret_basic", "https://client.example/disabled", []string{"openid", "profile"}, "client-secret")
	userRec := assertStatus(t, handler, http.MethodPost, "/api/admin/users", map[string]any{
		"name": "oidc-disabled-user", "type": "local", "status": "enabled", "password": "password123", "metadata": map[string]any{"role": "user"},
	}, adminCookie, http.StatusCreated)
	var user model.PlatformItem
	decodeResponse(t, userRec, &user)
	loginRec := assertStatus(t, handler, http.MethodPost, "/api/auth/login", map[string]any{"username": user.Name, "password": "password123"}, nil, http.StatusOK)
	code := issueOIDCHardeningCode(t, handler, loginRec.Result().Cookies()[0], "disabled-user-client", "https://client.example/disabled", "openid profile", "", "")
	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+user.ID, map[string]any{"status": "disabled"}, adminCookie, http.StatusOK)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://client.example/disabled"}}
	headers := map[string]string{"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte("disabled-user-client:client-secret"))}
	denied := performOIDCTokenRequest(handler, form, headers)
	if denied.Code != http.StatusBadRequest || !strings.Contains(denied.Body.String(), `"error":"invalid_grant"`) {
		t.Fatalf("disabled user code was not rejected: status=%d body=%s", denied.Code, denied.Body.String())
	}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/users/"+user.ID, map[string]any{"status": "enabled"}, adminCookie, http.StatusOK)
	if replay := performOIDCTokenRequest(handler, form, headers); replay.Code != http.StatusBadRequest {
		t.Fatalf("disabled-user authorization code was not consumed: status=%d body=%s", replay.Code, replay.Body.String())
	}
}

func createOIDCHardeningClient(t *testing.T, handler http.Handler, cookie *http.Cookie, clientID, clientType, method, redirect string, scopes []string, secret string) model.PlatformItem {
	t.Helper()
	rec := assertStatus(t, handler, http.MethodPost, "/api/admin/oidc-clients", map[string]any{
		"name": clientID, "type": clientType, "status": "enabled", "password": secret,
		"metadata": map[string]any{
			"client_id": clientID, "redirect_uris": []string{redirect}, "scopes": scopes, "token_endpoint_auth_method": method,
		},
	}, cookie, http.StatusCreated)
	var item model.PlatformItem
	decodeResponse(t, rec, &item)
	return item
}

func issueOIDCHardeningCode(t *testing.T, handler http.Handler, cookie *http.Cookie, clientID, redirectURI, scope, challenge, method string) string {
	t.Helper()
	query := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {scope}, "state": {"hardening-state"},
	}
	if challenge != "" {
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", method)
	}
	rec := assertStatus(t, handler, http.MethodGet, "/api/oidc/authorize?"+query.Encode(), nil, cookie, http.StatusFound)
	location, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("authorize did not issue code: %s", location.String())
	}
	return code
}

func performOIDCTokenRequest(handler http.Handler, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func decodeOIDCTestJWTClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}
