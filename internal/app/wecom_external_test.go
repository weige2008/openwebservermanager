package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"openwebservermanager/internal/model"
)

func TestWeComIdentitySettingValidationAndSecretLifecycle(t *testing.T) {
	handler, adminCookie := newTestHandler(t)

	valid := func() map[string]any {
		return map[string]any{
			"wecom_enabled":       true,
			"wecom_provider_id":   "corp-wecom",
			"wecom_provider_name": "Corp WeCom",
			"wecom_corp_id":       "ww-openweb",
			"wecom_agent_id":      "100001",
			"wecom_agent_secret":  "wecom-secret",
			"wecom_role":          "user",
			"wecom_auto_create":   true,
		}
	}

	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown field", mutate: func(metadata map[string]any) { metadata["wecom_enabeld"] = true }},
		{name: "wrong enabled type", mutate: func(metadata map[string]any) { metadata["wecom_enabled"] = "true" }},
		{name: "missing corp id", mutate: func(metadata map[string]any) { delete(metadata, "wecom_corp_id") }},
		{name: "missing secret", mutate: func(metadata map[string]any) { delete(metadata, "wecom_agent_secret") }},
		{name: "invalid agent id", mutate: func(metadata map[string]any) { metadata["wecom_agent_id"] = "agent-1" }},
		{name: "invalid role", mutate: func(metadata map[string]any) { metadata["wecom_role"] = "bad role" }},
		{name: "insecure remote endpoint", mutate: func(metadata map[string]any) { metadata["wecom_token_endpoint"] = "http://wecom.example.test/gettoken" }},
		{name: "endpoint credentials", mutate: func(metadata map[string]any) {
			metadata["wecom_token_endpoint"] = "https://user:password@wecom.example.test/gettoken"
		}},
		{name: "mismatched API origins", mutate: func(metadata map[string]any) {
			metadata["wecom_token_endpoint"] = "https://api-a.example.test/gettoken"
			metadata["wecom_userinfo_endpoint"] = "https://api-b.example.test/getuserinfo"
		}},
		{name: "private scope without agent", mutate: func(metadata map[string]any) {
			delete(metadata, "wecom_agent_id")
			metadata["wecom_scope"] = "snsapi_privateinfo"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			metadata := valid()
			test.mutate(metadata)
			assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
				"name": "Invalid Enterprise WeChat identity",
				"type": "identity", "status": "enabled", "metadata": metadata,
			}, adminCookie, http.StatusBadRequest)
		})
	}

	for name, metadata := range map[string]map[string]any{
		"unknown nested field": {
			"wecom_providers": []any{map[string]any{
				"id": "nested-wecom", "corp_id": "ww-openweb", "agent_secret": "secret", "unexpected": true,
			}},
		},
		"duplicate nested id": {
			"wecom_providers": []any{
				map[string]any{"id": "nested-wecom", "corp_id": "ww-one", "agent_secret": "secret-one"},
				map[string]any{"id": "nested-wecom", "corp_id": "ww-two", "agent_secret": "secret-two"},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
				"name": "Invalid nested Enterprise WeChat identity",
				"type": "identity", "status": "enabled", "metadata": metadata,
			}, adminCookie, http.StatusBadRequest)
		})
	}

	createdRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name": "Enterprise WeChat identity", "type": "identity", "status": "enabled", "metadata": valid(),
	}, adminCookie, http.StatusCreated)
	var created model.PlatformItem
	decodeResponse(t, createdRec, &created)
	raw, ok, err := handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if err != nil || !ok || firstMetadataString(raw.Metadata, "wecom_agent_secret_encrypted") == "" {
		t.Fatalf("load encrypted Enterprise WeChat setting: ok=%v err=%v metadata=%#v", ok, err, raw.Metadata)
	}
	originalCiphertext := firstMetadataString(raw.Metadata, "wecom_agent_secret_encrypted")

	kept := valid()
	delete(kept, "wecom_agent_secret")
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": kept}, adminCookie, http.StatusOK)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if firstMetadataString(raw.Metadata, "wecom_agent_secret_encrypted") != originalCiphertext {
		t.Fatal("Enterprise WeChat update did not preserve the existing encrypted secret")
	}

	clearWhileEnabled := cloneMetadata(kept)
	clearWhileEnabled["wecom_agent_secret_clear"] = true
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": clearWhileEnabled}, adminCookie, http.StatusBadRequest)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if firstMetadataString(raw.Metadata, "wecom_agent_secret_encrypted") != originalCiphertext {
		t.Fatal("rejected Enterprise WeChat clear changed the encrypted secret")
	}

	changedProvider := cloneMetadata(kept)
	changedProvider["wecom_provider_id"] = "replacement-wecom"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": changedProvider}, adminCookie, http.StatusBadRequest)
	changedProvider["wecom_agent_secret"] = "replacement-secret"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": changedProvider}, adminCookie, http.StatusOK)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if replacement := firstMetadataString(raw.Metadata, "wecom_agent_secret_encrypted"); replacement == "" || replacement == originalCiphertext {
		t.Fatal("replacement Enterprise WeChat provider did not receive a new encrypted secret")
	}

	disabledAndCleared := cloneMetadata(changedProvider)
	delete(disabledAndCleared, "wecom_agent_secret")
	disabledAndCleared["wecom_enabled"] = false
	disabledAndCleared["wecom_agent_secret_clear"] = true
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{"metadata": disabledAndCleared}, adminCookie, http.StatusOK)
	raw, _, _ = handler.(*Server).cfg.Store.GetPlatformItem("system_settings", created.ID)
	if firstMetadataString(raw.Metadata, "wecom_agent_secret_encrypted") != "" {
		t.Fatal("disabled Enterprise WeChat provider retained a cleared secret")
	}

	nestedRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name": "Nested Enterprise WeChat identity", "type": "identity", "status": "enabled",
		"metadata": map[string]any{"wecom_providers": []any{map[string]any{
			"id": "nested-wecom", "corp_id": "ww-nested", "agent_id": "100002", "agent_secret": "nested-secret",
		}}},
	}, adminCookie, http.StatusCreated)
	var nestedSetting model.PlatformItem
	decodeResponse(t, nestedRec, &nestedSetting)
	nestedWithoutSecret := map[string]any{"wecom_providers": []any{map[string]any{
		"id": "nested-wecom", "corp_id": "ww-nested", "agent_id": "100002",
	}}}
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+nestedSetting.ID, map[string]any{"metadata": nestedWithoutSecret}, adminCookie, http.StatusOK)
	nestedRenamed := cloneMetadata(nestedWithoutSecret)
	nestedRenamed["wecom_providers"].([]any)[0].(map[string]any)["id"] = "nested-replacement"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+nestedSetting.ID, map[string]any{"metadata": nestedRenamed}, adminCookie, http.StatusBadRequest)
}

func TestExternalWeComRequestsHonorCancellationRedactAndRejectRedirects(t *testing.T) {
	secret := "wecom secret+/=?:&"
	accessToken := "wecom access+/=?:&"
	code := "wecom code+/=?:&"

	t.Run("redirect", func(t *testing.T) {
		var sinkHits atomic.Int32
		sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			sinkHits.Add(1)
			writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": "redirected"})
		}))
		defer sink.Close()
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, sink.URL+"/stolen", http.StatusFound)
		}))
		defer providerServer.Close()
		provider := externalWeComProvider{CorpID: "ww-openweb", AgentSecret: secret, TokenEndpoint: providerServer.URL + "/gettoken"}
		_, err := testExternalWeComAccessToken(context.Background(), provider)
		if err == nil || !strings.Contains(err.Error(), "302") {
			t.Fatalf("redirecting Enterprise WeChat endpoint error = %v", err)
		}
		if sinkHits.Load() != 0 {
			t.Fatal("Enterprise WeChat client followed a credential-bearing redirect")
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		provider := externalWeComProvider{CorpID: "ww-openweb", AgentSecret: secret, TokenEndpoint: "http://127.0.0.1:1/gettoken"}
		started := time.Now()
		_, err := testExternalWeComAccessToken(ctx, provider)
		if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
			t.Fatalf("canceled Enterprise WeChat request error=%v duration=%s", err, time.Since(started))
		}
	})

	t.Run("total deadline and redaction", func(t *testing.T) {
		mode := atomic.Int32{}
		providerServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/gettoken":
				writeJSON(w, http.StatusOK, map[string]any{"errcode": 0, "access_token": accessToken, "expires_in": 7200})
			case "/getuserinfo":
				if mode.Load() == 0 {
					http.Error(w, "token="+accessToken+" code="+code, http.StatusBadGateway)
					return
				}
				<-r.Context().Done()
			default:
				http.NotFound(w, r)
			}
		}))
		defer providerServer.Close()
		provider := externalWeComProvider{
			CorpID: "ww-openweb", AgentSecret: secret,
			TokenEndpoint: providerServer.URL + "/gettoken", UserInfoEndpoint: providerServer.URL + "/getuserinfo",
		}
		_, err := (&Server{}).fetchExternalWeComClaims(context.Background(), provider, code)
		if err == nil || strings.Contains(err.Error(), accessToken) || strings.Contains(err.Error(), code) || !strings.Contains(err.Error(), "[redacted]") {
			t.Fatalf("Enterprise WeChat userinfo failure was not redacted: %v", err)
		}

		mode.Store(1)
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		started := time.Now()
		_, err = (&Server{}).fetchExternalWeComClaims(ctx, provider, code)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > time.Second {
			t.Fatalf("Enterprise WeChat total deadline error=%v duration=%s", err, time.Since(started))
		}
	})
}
