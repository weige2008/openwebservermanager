package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"openwebservermanager/internal/model"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

type ldapProtocolTestServer struct {
	listener        net.Listener
	tlsConfig       *tls.Config
	implicitTLS     bool
	allowStartTLS   bool
	stallAfterRead  bool
	serviceDN       string
	servicePassword string
	userDN          string
	userPassword    string

	mu          sync.Mutex
	tlsConfigMu sync.RWMutex
	connections map[net.Conn]struct{}
	bindNames   []string
	startTLS    int
	wg          sync.WaitGroup
}

func newLDAPProtocolTestServer(t *testing.T, implicitTLS, allowStartTLS, stallAfterRead bool) *ldapProtocolTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for LDAP test server: %v", err)
	}
	server := &ldapProtocolTestServer{
		listener:        listener,
		tlsConfig:       ldapProtocolTestTLSConfig(t),
		implicitTLS:     implicitTLS,
		allowStartTLS:   allowStartTLS,
		stallAfterRead:  stallAfterRead,
		serviceDN:       "cn=reader,dc=example,dc=test",
		servicePassword: "directory-secret",
		userDN:          "uid=ldap-probe,ou=people,dc=example,dc=test",
		userPassword:    "directory-password",
		connections:     map[net.Conn]struct{}{},
	}
	server.wg.Add(1)
	go server.serve()
	t.Cleanup(server.Close)
	return server
}

func ldapProtocolTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := fixture.TLS.Certificates[0]
	fixture.Close()
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	}
}

func (s *ldapProtocolTestServer) URL() string {
	scheme := "ldap"
	if s.implicitTLS {
		scheme = "ldaps"
	}
	return scheme + "://" + s.listener.Addr().String()
}

func (s *ldapProtocolTestServer) cloneTLSConfig() *tls.Config {
	s.tlsConfigMu.RLock()
	defer s.tlsConfigMu.RUnlock()
	return s.tlsConfig.Clone()
}

func (s *ldapProtocolTestServer) setTLSVersions(minimum, maximum uint16) {
	s.tlsConfigMu.Lock()
	defer s.tlsConfigMu.Unlock()
	s.tlsConfig.MinVersion = minimum
	s.tlsConfig.MaxVersion = maximum
}

func (s *ldapProtocolTestServer) Close() {
	_ = s.listener.Close()
	s.mu.Lock()
	for conn := range s.connections {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *ldapProtocolTestServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connections[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *ldapProtocolTestServer) handleConnection(rawConn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		delete(s.connections, rawConn)
		s.mu.Unlock()
		_ = rawConn.Close()
	}()
	conn := rawConn
	if s.implicitTLS {
		tlsConn := tls.Server(rawConn, s.cloneTLSConfig())
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		conn = tlsConn
	}
	serviceBound := false
	for {
		packet, err := ber.ReadPacket(conn)
		if err != nil {
			return
		}
		if len(packet.Children) < 2 {
			return
		}
		messageID, _ := packet.Children[0].Value.(int64)
		request := packet.Children[1]
		if s.stallAfterRead {
			_, _ = io.Copy(io.Discard, conn)
			return
		}
		switch request.Tag {
		case goldap.ApplicationBindRequest:
			if len(request.Children) < 3 {
				return
			}
			name, _ := request.Children[1].Value.(string)
			password := request.Children[2].Data.String()
			s.mu.Lock()
			s.bindNames = append(s.bindNames, name)
			s.mu.Unlock()
			valid := (name == s.serviceDN && password == s.servicePassword) || (name == s.userDN && password == s.userPassword)
			if valid && name == s.serviceDN {
				serviceBound = true
			}
			resultCode := uint64(goldap.LDAPResultSuccess)
			diagnostic := ""
			if !valid {
				resultCode = goldap.LDAPResultInvalidCredentials
				diagnostic = "invalid credentials"
			}
			if err := writeLDAPResult(conn, messageID, goldap.ApplicationBindResponse, resultCode, diagnostic); err != nil {
				return
			}
		case goldap.ApplicationSearchRequest:
			if !serviceBound {
				if err := writeLDAPResult(conn, messageID, goldap.ApplicationSearchResultDone, goldap.LDAPResultInsufficientAccessRights, "service bind required"); err != nil {
					return
				}
				continue
			}
			if err := writeLDAPSearchEntry(conn, messageID, s.userDN, map[string][]string{
				"uid":         {"ldap-probe"},
				"cn":          {"LDAP Probe"},
				"displayName": {"LDAP Protocol Probe"},
				"mail":        {"ldap-probe@example.test"},
				"memberOf":    {"cn=ops,ou=groups,dc=example,dc=test"},
			}); err != nil {
				return
			}
			if err := writeLDAPResult(conn, messageID, goldap.ApplicationSearchResultDone, goldap.LDAPResultSuccess, ""); err != nil {
				return
			}
		case goldap.ApplicationExtendedRequest:
			if !s.allowStartTLS || len(request.Children) == 0 || request.Children[0].Data.String() != "1.3.6.1.4.1.1466.20037" {
				if err := writeLDAPResult(conn, messageID, goldap.ApplicationExtendedResponse, goldap.LDAPResultUnavailable, "STARTTLS unavailable"); err != nil {
					return
				}
				continue
			}
			if err := writeLDAPResult(conn, messageID, goldap.ApplicationExtendedResponse, goldap.LDAPResultSuccess, ""); err != nil {
				return
			}
			s.mu.Lock()
			s.startTLS++
			s.mu.Unlock()
			tlsConn := tls.Server(conn, s.cloneTLSConfig())
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
		case goldap.ApplicationUnbindRequest:
			return
		default:
			return
		}
	}
}

func writeLDAPResult(writer io.Writer, messageID int64, applicationTag ber.Tag, resultCode uint64, diagnostic string) error {
	envelope := ber.NewSequence("LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, applicationTag, nil, "LDAP Result")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "Result Code"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnostic, "Diagnostic Message"))
	envelope.AppendChild(response)
	_, err := writer.Write(envelope.Bytes())
	return err
}

func writeLDAPSearchEntry(writer io.Writer, messageID int64, dn string, attributes map[string][]string) error {
	envelope := ber.NewSequence("LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, goldap.ApplicationSearchResultEntry, nil, "Search Result Entry")
	entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Object Name"))
	attributeList := ber.NewSequence("Attributes")
	for name, values := range attributes {
		attribute := ber.NewSequence("Attribute")
		attribute.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "Attribute Name"))
		valueSet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Attribute Values")
		for _, value := range values {
			valueSet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Attribute Value"))
		}
		attribute.AppendChild(valueSet)
		attributeList.AppendChild(attribute)
	}
	entry.AppendChild(attributeList)
	envelope.AppendChild(entry)
	_, err := writer.Write(envelope.Bytes())
	return err
}

func TestLDAPRealProtocolIntegration(t *testing.T) {
	directory := newLDAPProtocolTestServer(t, false, false, false)
	handler, adminCookie := newTestHandler(t)
	settingRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "LDAP protocol identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"ldap_enabled":                true,
			"ldap_provider_id":            "protocol-ldap",
			"ldap_provider_name":          "Protocol LDAP",
			"ldap_url":                    directory.URL(),
			"ldap_bind_dn":                directory.serviceDN,
			"ldap_bind_password":          directory.servicePassword,
			"ldap_base_dn":                "ou=people,dc=example,dc=test",
			"ldap_user_filter":            "(uid={username})",
			"ldap_username_attribute":     "uid",
			"ldap_display_name_attribute": "displayName",
			"ldap_email_attribute":        "mail",
			"ldap_role":                   "user",
			"ldap_auto_create":            true,
		},
	}, adminCookie, http.StatusCreated)
	var setting model.PlatformItem
	decodeResponse(t, settingRec, &setting)

	success := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   directory.userPassword,
	}, adminCookie, http.StatusOK)
	for _, expected := range []string{`"username":"ldap-probe"`, `"display_name":"LDAP Protocol Probe"`, `"email":"ldap-probe@example.test"`, "cn=ops"} {
		if !strings.Contains(success.Body.String(), expected) {
			t.Fatalf("real LDAP test response missing %q: %s", expected, success.Body.String())
		}
	}
	assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings/ldap/test", map[string]any{
		"setting_id": setting.ID,
		"username":   "ldap-probe",
		"password":   "wrong-password",
	}, adminCookie, http.StatusUnauthorized)
}

func TestLDAPRealProtocolTLSModes(t *testing.T) {
	for _, test := range []struct {
		name          string
		implicitTLS   bool
		allowStartTLS bool
		startTLS      bool
	}{
		{name: "STARTTLS", allowStartTLS: true, startTLS: true},
		{name: "LDAPS", implicitTLS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := newLDAPProtocolTestServer(t, test.implicitTLS, test.allowStartTLS, false)
			claims, ok, err := (realLDAPAuthenticator{}).Authenticate(context.Background(), externalLDAPProvider{
				ID:                   strings.ToLower(test.name),
				URL:                  directory.URL(),
				BindDN:               directory.serviceDN,
				BindPassword:         directory.servicePassword,
				BaseDN:               "ou=people,dc=example,dc=test",
				UserFilter:           "(uid={username})",
				UsernameAttribute:    "uid",
				DisplayNameAttribute: "cn",
				EmailAttribute:       "mail",
				Role:                 "user",
				StartTLS:             test.startTLS,
				InsecureSkipVerify:   true,
			}, "ldap-probe", directory.userPassword)
			if err != nil || !ok {
				t.Fatalf("authenticate through %s ok=%v err=%v", test.name, ok, err)
			}
			if claims.Email != "ldap-probe@example.test" {
				t.Fatalf("authenticate through %s claims = %#v", test.name, claims)
			}
			if test.startTLS {
				directory.mu.Lock()
				startTLSCalls := directory.startTLS
				directory.mu.Unlock()
				if startTLSCalls != 1 {
					t.Fatalf("STARTTLS calls = %d, want 1", startTLSCalls)
				}
			}
		})
	}
}

func TestLDAPUserDNTemplateEscapingAndUPNCompatibility(t *testing.T) {
	for _, test := range []struct {
		name       string
		template   string
		username   string
		wantBindDN string
	}{
		{name: "distinguished name", template: "uid={username},ou=people,dc=example,dc=test", username: "ops,dc=evil", wantBindDN: `uid=ops\,dc=evil,ou=people,dc=example,dc=test`},
		{name: "user principal name", template: "{username}@example.test", username: "ldap-probe", wantBindDN: "ldap-probe@example.test"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := newLDAPProtocolTestServer(t, false, false, false)
			directory.userDN = test.wantBindDN
			claims, ok, err := (realLDAPAuthenticator{}).Authenticate(context.Background(), externalLDAPProvider{
				ID:             "template-ldap",
				URL:            directory.URL(),
				UserDNTemplate: test.template,
				Role:           "user",
			}, test.username, directory.userPassword)
			if err != nil || !ok {
				t.Fatalf("template authentication ok=%v err=%v", ok, err)
			}
			if claims.DN != test.wantBindDN {
				t.Fatalf("template authentication DN = %q, want %q", claims.DN, test.wantBindDN)
			}
		})
	}
}

func TestLDAPAuthenticationCancellationAndTimeout(t *testing.T) {
	t.Run("dial cancellation", func(t *testing.T) {
		started := make(chan struct{})
		authenticator := realLDAPAuthenticator{
			timeout: 5 * time.Second,
			dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			},
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			_, _, err := authenticator.Authenticate(ctx, externalLDAPProvider{
				ID: "cancel-dial", URL: "ldap://127.0.0.1:389", UserDNTemplate: "{username}@example.test", Role: "user",
			}, "ldap-probe", "directory-password")
			done <- err
		}()
		<-started
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("dial cancellation error = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("LDAP dial did not stop after context cancellation")
		}
	})

	t.Run("operation cancellation", func(t *testing.T) {
		directory := newLDAPProtocolTestServer(t, false, false, true)
		authenticator := realLDAPAuthenticator{timeout: 5 * time.Second}
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		started := time.Now()
		_, _, err := authenticator.Authenticate(ctx, externalLDAPProvider{
			ID: "cancel-operation", URL: directory.URL(), UserDNTemplate: "{username}@example.test", Role: "user",
		}, "ldap-probe", directory.userPassword)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("operation cancellation error = %v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("operation cancellation took %s", elapsed)
		}
	})

	t.Run("total timeout", func(t *testing.T) {
		directory := newLDAPProtocolTestServer(t, false, false, true)
		authenticator := realLDAPAuthenticator{timeout: 50 * time.Millisecond}
		_, _, err := authenticator.Authenticate(context.Background(), externalLDAPProvider{
			ID: "timeout-operation", URL: directory.URL(), UserDNTemplate: "{username}@example.test", Role: "user",
		}, "ldap-probe", directory.userPassword)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("operation timeout error = %v", err)
		}
	})
}

func TestLDAPIdentitySettingValidation(t *testing.T) {
	handler, cookie := newTestHandler(t)
	base := func(metadata map[string]any) map[string]any {
		return map[string]any{"name": "LDAP validation", "type": "identity", "status": "enabled", "metadata": metadata}
	}
	for _, test := range []struct {
		name     string
		metadata map[string]any
		want     string
	}{
		{name: "unknown field", metadata: map[string]any{"ldap_enabled": false, "ldap_urll": "ldap://example.test"}, want: "not supported"},
		{name: "wrong boolean", metadata: map[string]any{"ldap_enabled": "yes"}, want: "must be a boolean"},
		{name: "URL credentials", metadata: map[string]any{"ldap_enabled": true, "ldap_url": "ldap://user:secret@example.test", "ldap_base_dn": "dc=example,dc=test"}, want: "must not contain credentials"},
		{name: "unsupported URL scheme", metadata: map[string]any{"ldap_enabled": true, "ldap_url": "https://example.test", "ldap_base_dn": "dc=example,dc=test"}, want: "scheme must be ldap or ldaps"},
		{name: "TLS conflict", metadata: map[string]any{"ldap_enabled": true, "ldap_url": "ldaps://example.test", "ldap_base_dn": "dc=example,dc=test", "ldap_start_tls": true}, want: "cannot be enabled"},
		{name: "missing search base", metadata: map[string]any{"ldap_enabled": true, "ldap_url": "ldap://example.test"}, want: "base DN or user DN template is required"},
		{name: "static filter", metadata: map[string]any{"ldap_enabled": true, "ldap_url": "ldap://example.test", "ldap_base_dn": "dc=example,dc=test", "ldap_user_filter": "(uid=admin)"}, want: "must contain the {username} placeholder"},
		{name: "invalid role", metadata: map[string]any{"ldap_enabled": true, "ldap_url": "ldap://example.test", "ldap_base_dn": "dc=example,dc=test", "ldap_role": "bad role"}, want: "default role is invalid"},
		{name: "malformed provider list", metadata: map[string]any{"ldap_providers": []any{"not-an-object"}}, want: "array of objects"},
		{name: "nested typo", metadata: map[string]any{"ldap_providers": []any{map[string]any{"enabled": false, "urll": "ldap://example.test"}}}, want: "not supported"},
	} {
		t.Run(test.name, func(t *testing.T) {
			rec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", base(test.metadata), cookie, http.StatusBadRequest)
			if !strings.Contains(rec.Body.String(), test.want) {
				t.Fatalf("LDAP validation error = %s, want %q", rec.Body.String(), test.want)
			}
		})
	}

	valid := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", base(map[string]any{
		"ldap_enabled":              true,
		"ldap_url":                  "ldap://directory.example.test:389",
		"ldap_user_dn_template":     "{username}@example.test",
		"ldap_role":                 "custom:operator",
		"ldap_insecure_skip_verify": false,
	}), cookie, http.StatusCreated)
	if !strings.Contains(valid.Body.String(), `"ldap_user_dn_template":"{username}@example.test"`) {
		t.Fatalf("valid LDAP UPN setting was not persisted: %s", valid.Body.String())
	}
	var validSetting model.PlatformItem
	decodeResponse(t, valid, &validSetting)
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+validSetting.ID, map[string]any{
		"metadata": map[string]any{
			"ldap_enabled":          true,
			"ldap_url":              "ftp://directory.example.test",
			"ldap_user_dn_template": "{username}@example.test",
		},
	}, cookie, http.StatusBadRequest)
	detail := assertStatus(t, handler, http.MethodGet, "/api/admin/system-settings/"+validSetting.ID, nil, cookie, http.StatusOK)
	if !strings.Contains(detail.Body.String(), `"ldap_url":"ldap://directory.example.test:389"`) {
		t.Fatalf("invalid LDAP patch changed persisted setting: %s", detail.Body.String())
	}
}

func TestLDAPNestedProviderSecretSurvivesSanitizedUpdate(t *testing.T) {
	handler, cookie := newTestHandler(t)
	server := handler.(*Server)
	createdRec := assertStatus(t, handler, http.MethodPost, "/api/admin/system-settings", map[string]any{
		"name":   "Nested LDAP identity",
		"type":   "identity",
		"status": "enabled",
		"metadata": map[string]any{
			"ldap_enabled": false,
			"ldap_providers": []any{
				map[string]any{
					"id":                     "nested-corp",
					"name":                   "Nested Corp",
					"enabled":                true,
					"url":                    "ldap://directory.example.test:389",
					"bind_dn":                "cn=reader,dc=example,dc=test",
					"ldap_bind_password":     "nested-directory-secret",
					"base_dn":                "ou=people,dc=example,dc=test",
					"user_filter":            "(uid={username})",
					"username_attribute":     "uid",
					"display_name_attribute": "cn",
					"email_attribute":        "mail",
					"role":                   "user",
				},
			},
		},
	}, cookie, http.StatusCreated)
	var created model.PlatformItem
	decodeResponse(t, createdRec, &created)
	providerList, ok := created.Metadata["ldap_providers"].([]any)
	if !ok || len(providerList) != 1 {
		t.Fatalf("sanitized nested LDAP providers = %#v", created.Metadata["ldap_providers"])
	}
	providerMetadata, ok := providerList[0].(map[string]any)
	if !ok || providerMetadata["ldap_bind_password_set"] != true {
		t.Fatalf("sanitized nested LDAP provider secret state = %#v", providerList[0])
	}
	for _, key := range []string{"ldap_bind_password", "ldap_bind_password_encrypted"} {
		if _, exists := providerMetadata[key]; exists {
			t.Fatalf("sanitized nested LDAP provider leaked %s: %#v", key, providerMetadata)
		}
	}
	providerMetadata["name"] = "Nested Corp Updated"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{
		"metadata": created.Metadata,
	}, cookie, http.StatusOK)

	raw, found, err := server.cfg.Store.GetPlatformItem("system_settings", created.ID)
	if err != nil || !found {
		t.Fatalf("get nested LDAP setting found=%v err=%v", found, err)
	}
	providers, err := server.externalLDAPProvidersFromMetadata(raw.Metadata)
	if err != nil {
		t.Fatalf("parse nested LDAP provider after update: %v", err)
	}
	if len(providers) != 1 || providers[0].BindPassword != "nested-directory-secret" || providers[0].Name != "Nested Corp Updated" {
		t.Fatalf("nested LDAP provider after sanitized update = %#v", providers)
	}

	providerMetadata["id"] = "replacement-corp"
	assertStatus(t, handler, http.MethodPatch, "/api/admin/system-settings/"+created.ID, map[string]any{
		"metadata": created.Metadata,
	}, cookie, http.StatusOK)
	raw, found, err = server.cfg.Store.GetPlatformItem("system_settings", created.ID)
	if err != nil || !found {
		t.Fatalf("get replaced nested LDAP setting found=%v err=%v", found, err)
	}
	providers, err = server.externalLDAPProvidersFromMetadata(raw.Metadata)
	if err != nil {
		t.Fatalf("parse replaced nested LDAP provider: %v", err)
	}
	if len(providers) != 1 || providers[0].ID != "replacement-corp" || providers[0].BindPassword != "" {
		t.Fatalf("replacement LDAP provider inherited old secret: %#v", providers)
	}
	rawProviders, _ := raw.Metadata["ldap_providers"].([]any)
	rawProvider, _ := rawProviders[0].(map[string]any)
	if rawProvider["ldap_bind_password_set"] == true || firstMetadataString(rawProvider, "ldap_bind_password_encrypted") != "" {
		t.Fatalf("replacement LDAP provider kept stale secret state: %#v", rawProvider)
	}
}

func TestLDAPMinimumTLSVersion(t *testing.T) {
	directory := newLDAPProtocolTestServer(t, true, false, false)
	directory.setTLSVersions(tls.VersionTLS10, tls.VersionTLS11)
	_, ok, err := (realLDAPAuthenticator{timeout: time.Second}).Authenticate(context.Background(), externalLDAPProvider{
		ID: "legacy-tls", URL: directory.URL(), UserDNTemplate: "{username}@example.test", Role: "user", InsecureSkipVerify: true,
	}, "ldap-probe", directory.userPassword)
	if err == nil || ok {
		t.Fatalf("legacy TLS LDAP authentication ok=%v err=%v", ok, err)
	}
	if !strings.Contains(strings.ToLower(fmt.Sprint(err)), "protocol") && !strings.Contains(strings.ToLower(fmt.Sprint(err)), "handshake") {
		t.Fatalf("legacy TLS error did not describe handshake failure: %v", err)
	}
}
