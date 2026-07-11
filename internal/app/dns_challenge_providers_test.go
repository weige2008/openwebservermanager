package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCloudflareDNSProviderCreatesAndCleansRecord(t *testing.T) {
	var mu sync.Mutex
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer cloudflare-secret" {
			t.Fatalf("unexpected Cloudflare authorization header %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/client/v4/zones":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": []map[string]any{{"id": "zone-1"}}})
		case r.Method == http.MethodPost && r.URL.Path == "/client/v4/zones/zone-1/dns_records":
			var payload map[string]any
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if payload["name"] != "_acme-challenge.api.example.test" || payload["content"] != "txt-value" {
				t.Fatalf("unexpected Cloudflare create payload: %#v", payload)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": "record-1"}})
		case r.Method == http.MethodDelete && r.URL.Path == "/client/v4/zones/zone-1/dns_records/record-1":
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := &cloudflareDNSProvider{client: server.Client(), baseURL: server.URL + "/client/v4", zone: "example.test", token: "cloudflare-secret"}
	cleanup, err := provider.Present(context.Background(), "_acme-challenge.api.example.test", "txt-value")
	if err != nil {
		t.Fatalf("present Cloudflare record: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup Cloudflare record: %v", err)
	}
	if strings.Join(requests, ",") != "GET /client/v4/zones,POST /client/v4/zones/zone-1/dns_records,DELETE /client/v4/zones/zone-1/dns_records/record-1" {
		t.Fatalf("unexpected Cloudflare request sequence: %#v", requests)
	}
}

func TestAliDNSProviderSignsCreateAndDelete(t *testing.T) {
	actions := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("AccessKeyId") != "aliyun-id" || query.Get("Signature") == "" {
			t.Fatalf("AliDNS request missing credentials/signature: %s", r.URL.RawQuery)
		}
		if strings.Contains(r.URL.RawQuery, "aliyun-secret") {
			t.Fatal("AliDNS secret leaked into query")
		}
		actions = append(actions, query.Get("Action"))
		switch query.Get("Action") {
		case "AddDomainRecord":
			if query.Get("DomainName") != "example.test" || query.Get("RR") != "_acme-challenge.api" || query.Get("Value") != "txt-value" {
				t.Fatalf("unexpected AliDNS add query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"RecordId": "record-2"})
		case "DeleteDomainRecord":
			if query.Get("RecordId") != "record-2" {
				t.Fatalf("unexpected AliDNS delete query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"RequestId": "ok"})
		default:
			http.Error(w, "unexpected action", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	provider := &aliDNSProvider{client: server.Client(), baseURL: server.URL, zone: "example.test", accessKeyID: "aliyun-id", secret: "aliyun-secret"}
	cleanup, err := provider.Present(context.Background(), "_acme-challenge.api.example.test", "txt-value")
	if err != nil {
		t.Fatalf("present AliDNS record: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup AliDNS record: %v", err)
	}
	if strings.Join(actions, ",") != "AddDomainRecord,DeleteDomainRecord" {
		t.Fatalf("unexpected AliDNS actions: %#v", actions)
	}
}

func TestDNSPodProviderCreatesAndCleansRecord(t *testing.T) {
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("login_token") != "12345,dnspod-secret" {
			t.Fatalf("unexpected DNSPod token: %q", r.Form.Get("login_token"))
		}
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/Record.Create":
			if r.Form.Get("sub_domain") != "_acme-challenge.api" || r.Form.Get("value") != "txt-value" {
				t.Fatalf("unexpected DNSPod create form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"code": "1"}, "record": map[string]any{"id": "record-3"}})
		case "/Record.Remove":
			if r.Form.Get("record_id") != "record-3" {
				t.Fatalf("unexpected DNSPod remove form: %#v", r.Form)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"code": "1"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := &dnsPodProvider{client: server.Client(), baseURL: server.URL, zone: "example.test", token: "12345,dnspod-secret"}
	cleanup, err := provider.Present(context.Background(), "_acme-challenge.api.example.test", "txt-value")
	if err != nil {
		t.Fatalf("present DNSPod record: %v", err)
	}
	if err := cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup DNSPod record: %v", err)
	}
	if strings.Join(paths, ",") != "/Record.Create,/Record.Remove" {
		t.Fatalf("unexpected DNSPod paths: %#v", paths)
	}
}

type sequenceTXTResolver struct {
	values [][]string
	calls  int
}

func (r *sequenceTXTResolver) LookupTXT(_ context.Context, _ string) ([]string, error) {
	r.calls++
	if len(r.values) == 0 {
		return nil, errors.New("not propagated")
	}
	value := r.values[0]
	r.values = r.values[1:]
	return value, nil
}

func TestPropagatingDNSProviderWaitsAndCleansOnTimeout(t *testing.T) {
	base := &fakeDNSChallengeProvider{}
	resolver := &sequenceTXTResolver{values: [][]string{{"old"}, {"txt-value"}}}
	provider := &propagatingDNSProvider{provider: base, resolver: resolver, timeout: time.Second, interval: time.Millisecond}
	cleanup, err := provider.Present(context.Background(), "_acme-challenge.example.test", "txt-value")
	if err != nil || resolver.calls != 2 {
		t.Fatalf("propagation wait failed: calls=%d err=%v", resolver.calls, err)
	}
	if err := cleanup(context.Background()); err != nil || base.cleaned != 1 {
		t.Fatalf("propagated record cleanup failed: cleaned=%d err=%v", base.cleaned, err)
	}

	timedBase := &fakeDNSChallengeProvider{}
	timed := &propagatingDNSProvider{provider: timedBase, resolver: &sequenceTXTResolver{}, timeout: 5 * time.Millisecond, interval: time.Millisecond}
	if _, err := timed.Present(context.Background(), "_acme-challenge.example.test", "missing"); err == nil || timedBase.cleaned != 1 {
		t.Fatalf("timed out propagation did not clean record: cleaned=%d err=%v", timedBase.cleaned, err)
	}
}

func TestDNSProviderHelpersRejectOutsideZoneAndUnsupportedProvider(t *testing.T) {
	if _, err := relativeDNSRecordName("_acme-challenge.other.test", "example.test"); err == nil {
		t.Fatal("outside-zone DNS record was accepted")
	}
	if got := dnsChallengeRecordName("*.Example.Test."); got != "_acme-challenge.example.test" {
		t.Fatalf("wildcard challenge name = %q", got)
	}
	if _, err := (realDNSChallengeProviderFactory{}).New(DNSProviderConfig{Provider: "unknown"}); err == nil {
		t.Fatal("unsupported DNS provider was accepted")
	}
}

func TestDNSProviderHTTPErrorDoesNotExposeRequestToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"denied"}`, http.StatusForbidden)
	}))
	defer server.Close()
	provider := &cloudflareDNSProvider{client: server.Client(), baseURL: server.URL, zone: "example.test", token: "must-not-leak"}
	_, err := provider.Present(context.Background(), "_acme-challenge.example.test", "value")
	if err == nil || strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("unsafe provider error: %v", err)
	}
}
