package app

import (
	"context"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openwebservermanager/internal/model"
)

func TestOIDCIdentitySettingValidationAndSecretLifecycle(t *testing.T) {
	handler, adminCookie := newTestHandler(t)
	valid := func() map[string]any {
		return map[string]any{
			"oidc_login_enabled":              true,
			"oidc_provider_id":                "corp-oidc",
			"oidc_provider_name":              "Corp OIDC",
			"oidc_issuer":                     "https://sso.example.test",
			"oidc_authorization_endpoint":     "https://sso.example.test/oauth2/authorize",
			"oidc_token_endpoint":             "https://sso.example.test/oauth2/token",
			"oidc_userinfo_endpoint":          "https://sso.example.test/oauth2/userinfo",
			"oidc_jwks_uri":                   "https://sso.example.test/oauth2/jwks",
			"oidc_client_id":                  "openweb-client",
			"oidc_client_secret":              "openweb-secret",
			"oidc_scopes":                     []string{"openid", "profile", "email"},
			"oidc_token_endpoint_auth_method": "client_secret_basic",
			"oidc_require_id_token":           true,
			"oidc_role":                       "user",
			"oidc_auto_create":                true,
		}
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown field", mutate: func(metadata map[string]any) { metadata["oidc_tokn_endpoint"] = "https://sso.example.test/token" }},
		{name: "wrong enabled type", mutate: func(metadata map[string]any) { metadata["oidc_login_enabled"] = "true" }},
		{name: "missing issuer", mutate: func(metadata map[string]any) { delete(metadata, "oidc_issuer") }},
		{name: "missing client secret", mutate: func(metadata map[string]any) { delete(metadata, "oidc_client_secret") }},
		{name: "missing openid scope", mutate: func(metadata map[string]any) { metadata["oidc_scopes"] = []string{"profile", "email"} }},
		{name: "invalid auth method", mutate: func(metadata map[string]any) { metadata["oidc_token_endpoint_auth_method"] = "password" }},
		{name: "invalid role", mutate: func(metadata map[string]any) { metadata["oidc_role"] = "bad role" }},
		{name: "insecure remote endpoint", mutate: func(metadata map[string]any) { metadata["oidc_token_endpoint"] = "http://sso.example.test/token" }},
		{name: "endpoint credentials", mutate: func(metadata map[string]any) {
			metadata["oidc_jwks_uri"] = "https://user:password@sso.example.test/jwks"
		}},
		{name: "token query", mutate: func(metadata map[string]any) {
			metadata["oidc_token_endpoint"] = "https://sso.example.test/token?tenant=one"
		}},
		{name: "endpoint fragment", mutate: func(metadata map[string]any) {
			metadata["oidc_authorization_endpoint"] = "https://sso.example.test/authorize#fragment"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := valid()
			test.mutate(metadata)
			assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
				"name": "Invalid OIDC", "type": "identity", "status": "enabled", "metadata": metadata,
			}, adminCookie, http.StatusBadRequest)
		})
	}

	for name, metadata := range map[string]map[string]any{
		"unknown nested field": {
			"oidc_providers": []any{map[string]any{
				"id": "nested", "authorization_endpoint": "https://sso.example.test/authorize", "token_endpoint": "https://sso.example.test/token", "userinfo_endpoint": "https://sso.example.test/userinfo", "client_id": "client", "client_secret": "secret", "scopes": []string{"openid"}, "unexpected": true,
			}},
		},
		"duplicate nested id": {
			"oidc_providers": []any{
				map[string]any{"id": "nested", "authorization_endpoint": "https://sso.example.test/authorize", "token_endpoint": "https://sso.example.test/token", "userinfo_endpoint": "https://sso.example.test/userinfo", "client_id": "one", "client_secret": "secret", "scopes": []string{"openid"}},
				map[string]any{"id": "nested", "authorization_endpoint": "https://sso.example.test/authorize", "token_endpoint": "https://sso.example.test/token", "userinfo_endpoint": "https://sso.example.test/userinfo", "client_id": "two", "client_secret": "secret", "scopes": []string{"openid"}},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
				"name": "Invalid nested OIDC", "type": "identity", "status": "enabled", "metadata": metadata,
			}, adminCookie, http.StatusBadRequest)
		})
	}

	createdRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name": "External OIDC identity", "type": "identity", "status": "enabled", "metadata": valid(),
	}, adminCookie, http.StatusCreated)
	var created model.PlatformItem
	decodeResponse(t, createdRec, &created)
	raw, ok, err := handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if err != nil || !ok || firstMetadataString(raw.Metadata, "oidc_client_secret_encrypted") == "" {
		t.Fatalf("load encrypted OIDC setting: ok=%v err=%v metadata=%#v", ok, err, raw.Metadata)
	}
	originalCiphertext := firstMetadataString(raw.Metadata, "oidc_client_secret_encrypted")

	kept := valid()
	delete(kept, "oidc_client_secret")
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": kept}, adminCookie, http.StatusOK)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if firstMetadataString(raw.Metadata, "oidc_client_secret_encrypted") != originalCiphertext {
		t.Fatal("OIDC update did not preserve the existing encrypted client secret")
	}

	clearEnabled := cloneMetadata(kept)
	clearEnabled["oidc_client_secret_clear"] = true
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": clearEnabled}, adminCookie, http.StatusBadRequest)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if firstMetadataString(raw.Metadata, "oidc_client_secret_encrypted") != originalCiphertext {
		t.Fatal("rejected OIDC clear changed the encrypted client secret")
	}

	changedProvider := cloneMetadata(kept)
	changedProvider["oidc_provider_id"] = "replacement-oidc"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": changedProvider}, adminCookie, http.StatusBadRequest)
	changedProvider["oidc_client_secret"] = "replacement-secret"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": changedProvider}, adminCookie, http.StatusOK)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if replacement := firstMetadataString(raw.Metadata, "oidc_client_secret_encrypted"); replacement == "" || replacement == originalCiphertext {
		t.Fatal("replacement OIDC provider did not receive a new encrypted secret")
	}

	publicClient := cloneMetadata(changedProvider)
	delete(publicClient, "oidc_client_secret")
	publicClient["oidc_token_endpoint_auth_method"] = "none"
	publicClient["oidc_client_secret_clear"] = true
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": publicClient}, adminCookie, http.StatusOK)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if firstMetadataString(raw.Metadata, "oidc_client_secret_encrypted") != "" {
		t.Fatal("public OIDC client retained a cleared client secret")
	}
}

func TestExternalOIDCTransportAndVerifiedUserInfo(t *testing.T) {
	t.Run("discovery requires exact issuer", func(t *testing.T) {
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				writeJSON(w, http.StatusOK, map[string]any{"jwks_uri": "https://sso.example.test/jwks"})
			default:
				http.NotFound(w, r)
			}
		}))
		defer providerServer.Close()
		_, _, err := externalOIDCJWKSURI(context.Background(), externalOIDCHTTPClient(), externalOIDCProvider{Issuer: providerServer.URL})
		if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
			t.Fatalf("OIDC discovery without issuer was accepted: %v", err)
		}
	})

	t.Run("oversized jwk exponent is rejected", func(t *testing.T) {
		modulus := new(big.Int).Lsh(big.NewInt(1), 2047)
		_, err := rsaPublicKeyFromJWK(externalOIDCJWK{
			N: base64.RawURLEncoding.EncodeToString(modulus.Bytes()),
			E: base64.RawURLEncoding.EncodeToString([]byte{1, 0, 0, 0, 0, 0, 0, 0, 3}),
		})
		if err == nil || !strings.Contains(err.Error(), "exponent is invalid") {
			t.Fatalf("oversized OIDC JWK exponent was accepted: %v", err)
		}
	})

	t.Run("token redirect is rejected", func(t *testing.T) {
		var sinkHits atomic.Int32
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			sinkHits.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"access_token": "stolen", "token_type": "Bearer"})
		}))
		defer sink.Close()
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, sink.URL+"/token", http.StatusFound)
		}))
		defer providerServer.Close()
		provider := externalOIDCProvider{TokenEndpoint: providerServer.URL + "/token", ClientID: "client", ClientSecret: "secret", TokenAuthMethod: "client_secret_basic", UserInfoEndpoint: providerServer.URL + "/userinfo"}
		req := httptest.NewRequest(http.MethodGet, "http://manager.test/api/auth/oidc/callback", nil)
		_, err := (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if err == nil || !strings.Contains(err.Error(), "302") || sinkHits.Load() != 0 {
			t.Fatalf("OIDC token redirect error=%v sink_hits=%d", err, sinkHits.Load())
		}
	})

	t.Run("request cancellation and total deadline", func(t *testing.T) {
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(250 * time.Millisecond):
				http.Error(w, "request remained open", http.StatusGatewayTimeout)
			}
		}))
		defer providerServer.Close()
		provider := externalOIDCProvider{TokenEndpoint: providerServer.URL + "/token", ClientID: "client", ClientSecret: "secret", TokenAuthMethod: "client_secret_basic", UserInfoEndpoint: providerServer.URL + "/userinfo"}

		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		req := httptest.NewRequest(http.MethodGet, "http://manager.test/api/auth/oidc/callback", nil).WithContext(canceled)
		started := time.Now()
		_, err := (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
			t.Fatalf("canceled OIDC request error=%v duration=%s", err, time.Since(started))
		}

		deadline, deadlineCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer deadlineCancel()
		req = httptest.NewRequest(http.MethodGet, "http://manager.test/api/auth/oidc/callback", nil).WithContext(deadline)
		started = time.Now()
		_, err = (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("deadline OIDC request error=%v duration=%s", err, time.Since(started))
		}
	})

	t.Run("verified subject mismatch", func(t *testing.T) {
		signer := newOIDCManager()
		var providerURL string
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/token":
				idToken, err := signer.signJWT(map[string]any{
					"iss": providerURL, "sub": "verified-subject", "aud": "client", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(), "nonce": "nonce",
				})
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"access_token": "access", "token_type": "Bearer", "id_token": idToken})
			case "/jwks":
				writeJSON(w, http.StatusOK, externalOIDCTestJWKS(signer))
			case "/userinfo":
				writeJSON(w, http.StatusOK, map[string]any{"sub": "replaced-subject", "preferred_username": "attacker"})
			default:
				http.NotFound(w, r)
			}
		}))
		defer providerServer.Close()
		providerURL = providerServer.URL
		provider := externalOIDCProvider{
			Issuer: providerURL, TokenEndpoint: providerURL + "/token", UserInfoEndpoint: providerURL + "/userinfo", JWKSEndpoint: providerURL + "/jwks",
			ClientID: "client", ClientSecret: "secret", TokenAuthMethod: "client_secret_basic", RequireIDToken: true,
		}
		req := httptest.NewRequest(http.MethodGet, "http://manager.test/api/auth/oidc/callback", nil)
		_, err := (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if err == nil || !strings.Contains(err.Error(), "subject does not match") {
			t.Fatalf("OIDC accepted mismatched UserInfo subject: %v", err)
		}
	})

	t.Run("required id token and public client", func(t *testing.T) {
		var userInfoCalls atomic.Int32
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/token":
				if _, _, ok := r.BasicAuth(); ok || r.FormValue("client_secret") != "" {
					http.Error(w, "unexpected client secret", http.StatusBadRequest)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"access_token": "public-access", "token_type": "Bearer"})
			case "/userinfo":
				userInfoCalls.Add(1)
				writeJSON(w, http.StatusOK, map[string]any{"sub": "public-subject", "preferred_username": "public-user"})
			default:
				http.NotFound(w, r)
			}
		}))
		defer providerServer.Close()
		provider := externalOIDCProvider{Issuer: providerServer.URL, TokenEndpoint: providerServer.URL + "/token", UserInfoEndpoint: providerServer.URL + "/userinfo", ClientID: "public-client", TokenAuthMethod: "none", RequireIDToken: true}
		req := httptest.NewRequest(http.MethodGet, "http://manager.test/api/auth/oidc/callback", nil)
		_, err := (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if err == nil || !strings.Contains(err.Error(), "missing required id_token") || userInfoCalls.Load() != 0 {
			t.Fatalf("required ID token result error=%v userinfo_calls=%d", err, userInfoCalls.Load())
		}

		provider.RequireIDToken = false
		claims, err := (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if err != nil || firstMetadataString(claims, "sub") != "public-subject" {
			t.Fatalf("public OIDC client login claims=%v error=%v", claims, err)
		}
	})

	t.Run("client secret post", func(t *testing.T) {
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/token":
				if _, _, ok := r.BasicAuth(); ok || r.FormValue("client_id") != "post-client" || r.FormValue("client_secret") != "post-secret" {
					http.Error(w, "invalid client_secret_post request", http.StatusUnauthorized)
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"access_token": "post-access", "token_type": "Bearer"})
			case "/userinfo":
				writeJSON(w, http.StatusOK, map[string]any{"sub": "post-subject", "preferred_username": "post-user"})
			default:
				http.NotFound(w, r)
			}
		}))
		defer providerServer.Close()
		provider := externalOIDCProvider{TokenEndpoint: providerServer.URL + "/token", UserInfoEndpoint: providerServer.URL + "/userinfo", ClientID: "post-client", ClientSecret: "post-secret", TokenAuthMethod: "client_secret_post"}
		req := httptest.NewRequest(http.MethodGet, "http://manager.test/api/auth/oidc/callback", nil)
		claims, err := (&Server{}).exchangeExternalOIDCCode(req, provider, "code", "nonce", "verifier")
		if err != nil || firstMetadataString(claims, "sub") != "post-subject" {
			t.Fatalf("client_secret_post claims=%v error=%v", claims, err)
		}
	})
}

func TestSafeRedirectPathRejectsBackslashAndExternalForms(t *testing.T) {
	for _, value := range []string{"//evil.example/path", "/\\evil.example/path", "/\r\nLocation: https://evil.example", "https://evil.example/path", "javascript:alert(1)"} {
		if got := safeRedirectPath(value); got != "/app" {
			t.Fatalf("safeRedirectPath(%q) = %q, want /app", value, got)
		}
	}
	if got := safeRedirectPath("/app/access?group=prod"); got != "/app/access?group=prod" {
		t.Fatalf("safe internal redirect changed to %q", got)
	}
}
