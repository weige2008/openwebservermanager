package app

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"

	"golang.org/x/crypto/bcrypt"
)

const (
	oidcAuthorizationCodeTTL = 5 * time.Minute
	oidcAccessTokenTTL       = time.Hour
)

type oidcManager struct {
	mu           sync.Mutex
	privateKey   *rsa.PrivateKey
	keyID        string
	codes        map[string]oidcAuthorizationCode
	accessTokens map[string]oidcAccessToken
	store        *store.Store
}

type oidcAuthorizationCode struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
	Username            string
	Role                string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

type oidcAccessToken struct {
	ClientID  string
	Scope     string
	UserID    string
	Username  string
	Role      string
	ExpiresAt time.Time
}

type oidcClientCredentials struct {
	ClientID     string
	ClientSecret string
}

func newOIDCManager(stores ...*store.Store) *oidcManager {
	var st *store.Store
	if len(stores) > 0 {
		st = stores[0]
	}
	key, err := loadOrCreateOIDCSigningKey(st)
	if err != nil {
		panic(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		panic(err)
	}
	keyHash := sha256.Sum256(publicDER)
	return &oidcManager{
		privateKey:   key,
		keyID:        base64.RawURLEncoding.EncodeToString(keyHash[:12]),
		codes:        map[string]oidcAuthorizationCode{},
		accessTokens: map[string]oidcAccessToken{},
		store:        st,
	}
}

func loadOrCreateOIDCSigningKey(st *store.Store) (*rsa.PrivateKey, error) {
	if st != nil {
		item, ok, err := st.GetPlatformItem("oidc_runtime", "signing-key-v1")
		if err != nil {
			return nil, fmt.Errorf("load OIDC signing key: %w", err)
		}
		if ok {
			encrypted := firstMetadataString(item.Metadata, "private_key_encrypted")
			if encrypted == "" {
				return nil, errors.New("persisted OIDC signing key is missing encrypted key material")
			}
			encoded, err := st.DecryptPlatformSecret(encrypted)
			if err != nil {
				return nil, fmt.Errorf("decrypt OIDC signing key: %w", err)
			}
			return parseOIDCSigningKey(encoded)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if st == nil {
		return key, nil
	}
	encoded := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	encrypted, err := st.EncryptPlatformSecret(encoded)
	if err != nil {
		return nil, fmt.Errorf("encrypt OIDC signing key: %w", err)
	}
	_, err = st.SavePlatformItem("oidc_runtime", model.PlatformItem{
		ID: "signing-key-v1", Name: "OIDC signing key", Type: "signing-key", Status: "active",
		Metadata: map[string]any{"private_key_encrypted": encrypted, "created_at": time.Now().UTC().Format(time.RFC3339Nano)},
	})
	if err != nil {
		return nil, fmt.Errorf("persist OIDC signing key: %w", err)
	}
	return key, nil
}

func parseOIDCSigningKey(encoded string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("decode OIDC signing key: invalid PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC signing key: %w", err)
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("validate OIDC signing key: %w", err)
	}
	return key, nil
}

func (s *Server) handleOIDCAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/oidc/jwks":
		s.handleOIDCJWKS(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/api/oidc/authorize":
		s.handleOIDCAuthorize(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/oidc/token":
		s.handleOIDCToken(w, r)
	case (r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == "/api/oidc/userinfo":
		s.handleOIDCUserInfo(w, r)
	default:
		writeError(w, http.StatusNotFound, "oidc endpoint not found")
	}
}

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	issuer := requestBaseURL(r, s.cfg.TrustProxyHeaders)
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/api/oidc/authorize",
		"token_endpoint":                        issuer + "/api/oidc/token",
		"userinfo_endpoint":                     issuer + "/api/oidc/userinfo",
		"jwks_uri":                              issuer + "/api/oidc/jwks",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username", "role"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
		"prompt_values_supported":               []string{"none", "login", "consent", "select_account"},
	})
}

func (s *Server) handleOIDCJWKS(w http.ResponseWriter, _ *http.Request) {
	publicKey := s.oidc.privateKey.Public().(*rsa.PublicKey)
	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"kid": s.oidc.keyID,
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}},
	})
}

func (s *Server) handleOIDCAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	client, err := s.oidcClientByID(query.Get("client_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	redirectURI := strings.TrimSpace(query.Get("redirect_uri"))
	if !oidcRedirectAllowed(client, redirectURI) {
		writeError(w, http.StatusBadRequest, "redirect_uri is not allowed for client")
		return
	}
	if query.Get("response_type") != "code" {
		s.redirectOIDCError(w, r, redirectURI, "unsupported_response_type", "only the authorization code flow is supported")
		return
	}
	if responseMode := strings.TrimSpace(query.Get("response_mode")); responseMode != "" && responseMode != "query" {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "only query response_mode is supported")
		return
	}
	scope, err := oidcValidateScope(client, query.Get("scope"))
	if err != nil {
		s.redirectOIDCError(w, r, redirectURI, "invalid_scope", err.Error())
		return
	}
	codeChallenge := strings.TrimSpace(query.Get("code_challenge"))
	codeChallengeMethod := strings.TrimSpace(query.Get("code_challenge_method"))
	if codeChallenge == "" && codeChallengeMethod != "" {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "code_challenge_method requires code_challenge")
		return
	}
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "plain"
	}
	if codeChallenge != "" && codeChallengeMethod != "plain" && codeChallengeMethod != "S256" {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "unsupported code_challenge_method")
		return
	}
	if codeChallenge != "" && !oidcPKCEValueValid(codeChallenge) {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "code_challenge must be 43-128 RFC 7636 unreserved characters")
		return
	}
	if oidcClientRequiresPKCE(client) && codeChallenge == "" {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "public clients must use PKCE")
		return
	}
	prompts, err := oidcPromptValues(query.Get("prompt"))
	if err != nil {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", err.Error())
		return
	}
	maxAge, hasMaxAge, err := oidcMaxAge(query.Get("max_age"))
	if err != nil {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", err.Error())
		return
	}
	token, session, ok := s.authSession(r)
	if !ok {
		if prompts["none"] {
			s.redirectOIDCError(w, r, redirectURI, "login_required", "user is not signed in")
			return
		}
		s.redirectOIDCLogin(w, r, false)
		return
	}
	requiresReauthentication := session.AuthTime.IsZero() || prompts["login"] || prompts["select_account"]
	if hasMaxAge && (maxAge == 0 || time.Since(session.AuthTime) > maxAge) {
		requiresReauthentication = true
	}
	if requiresReauthentication {
		if prompts["none"] {
			s.redirectOIDCError(w, r, redirectURI, "login_required", "user authentication is too old")
			return
		}
		if err := s.revokeAuthSession(r, token, session); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		http.SetCookie(w, s.authCookie(r, "", -1))
		_ = s.audit(r, "oidc.reauthenticate", oidcClientID(client), "", "OIDC request requires fresh authentication")
		s.redirectOIDCLogin(w, r, true)
		return
	}
	code, err := s.oidc.createAuthorizationCode(oidcAuthorizationCode{
		ClientID:            oidcClientID(client),
		RedirectURI:         redirectURI,
		Scope:               scope,
		Nonce:               query.Get("nonce"),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		UserID:              session.UserID,
		Username:            session.Username,
		Role:                session.Role,
		AuthTime:            session.AuthTime,
		ExpiresAt:           time.Now().UTC().Add(oidcAuthorizationCodeTTL),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	location, _ := url.Parse(redirectURI)
	values := location.Query()
	values.Set("code", code)
	if state := query.Get("state"); state != "" {
		values.Set("state", state)
	}
	location.RawQuery = values.Encode()
	_ = s.audit(r, "oidc.authorize", oidcClientID(client), "", "issued authorization code")
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func oidcPromptValues(raw string) (map[string]bool, error) {
	result := map[string]bool{}
	for _, value := range strings.Fields(strings.TrimSpace(raw)) {
		switch value {
		case "none", "login", "consent", "select_account":
			result[value] = true
		default:
			return nil, fmt.Errorf("unsupported prompt value %q", value)
		}
	}
	if result["none"] && len(result) > 1 {
		return nil, errors.New("prompt none cannot be combined with other values")
	}
	return result, nil
}

func oidcMaxAge(raw string) (time.Duration, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false, nil
	}
	seconds, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || seconds < 0 {
		return 0, false, errors.New("max_age must be a non-negative integer")
	}
	if seconds > int64((time.Duration(1<<63-1))/time.Second) {
		return 0, false, errors.New("max_age is too large")
	}
	return time.Duration(seconds) * time.Second, true, nil
}

func (s *Server) redirectOIDCLogin(w http.ResponseWriter, r *http.Request, reauthenticate bool) {
	nextURL := *r.URL
	query := nextURL.Query()
	if reauthenticate {
		query.Del("prompt")
		query.Del("max_age")
	}
	nextURL.RawQuery = query.Encode()
	values := url.Values{"next": {nextURL.RequestURI()}}
	if reauthenticate {
		values.Set("reauth", "1")
	}
	http.Redirect(w, r, "/login?"+values.Encode(), http.StatusFound)
}

func (s *Server) handleOIDCToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid token request")
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeError(w, http.StatusBadRequest, "unsupported grant_type")
		return
	}
	credentials := oidcClientCredentialsFromRequest(r)
	client, err := s.oidcClientByID(credentials.ClientID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid client")
		return
	}
	if !oidcClientSecretValid(client, credentials.ClientSecret) {
		writeError(w, http.StatusUnauthorized, "invalid client")
		return
	}
	redirectURI := strings.TrimSpace(r.PostForm.Get("redirect_uri"))
	codeValue := r.PostForm.Get("code")
	code, err := s.oidc.consumeAuthorizationCode(codeValue, oidcClientID(client), redirectURI, r.PostForm.Get("code_verifier"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	issuer := requestBaseURL(r, s.cfg.TrustProxyHeaders)
	if err := s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "oidc.token",
		Type:        "oidc",
		Status:      "success",
		OwnerID:     code.UserID,
		TargetID:    code.ClientID,
		Description: "issued oidc tokens",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "client_id": code.ClientID, "scope": code.Scope},
	}); err != nil {
		if restoreErr := s.oidc.restoreAuthorizationCode(codeValue, code); restoreErr != nil {
			err = fmt.Errorf("%w; additionally restore authorization code: %v", err, restoreErr)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	idToken, err := s.oidc.signIDToken(issuer, code)
	if err != nil {
		if restoreErr := s.oidc.restoreAuthorizationCode(codeValue, code); restoreErr != nil {
			err = fmt.Errorf("%w; additionally restore authorization code: %v", err, restoreErr)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	accessToken, err := s.oidc.createAccessToken(oidcAccessToken{
		ClientID:  code.ClientID,
		Scope:     code.Scope,
		UserID:    code.UserID,
		Username:  code.Username,
		Role:      code.Role,
		ExpiresAt: time.Now().UTC().Add(oidcAccessTokenTTL),
	})
	if err != nil {
		if restoreErr := s.oidc.restoreAuthorizationCode(codeValue, code); restoreErr != nil {
			err = fmt.Errorf("%w; additionally restore authorization code: %v", err, restoreErr)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(oidcAccessTokenTTL.Seconds()),
		"scope":        code.Scope,
		"id_token":     idToken,
	})
}

func (s *Server) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	token := oidcBearerTokenFromRequest(r)
	if token == "" {
		writeError(w, http.StatusUnauthorized, "bearer token required")
		return
	}
	accessToken, ok, err := s.oidc.accessToken(token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}
	if _, err := s.oidcClientByID(accessToken.ClientID); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}
	user, ok, err := s.authUserByID(accessToken.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "invalid bearer token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":                user.UserID,
		"name":               user.Username,
		"preferred_username": user.Username,
		"role":               user.Role,
	})
}

func oidcBearerTokenFromRequest(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader != "" {
		parts := strings.Fields(authHeader)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	if r.Method != http.MethodPost {
		return ""
	}
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return strings.TrimSpace(r.PostForm.Get("access_token"))
}

func (s *Server) redirectOIDCError(w http.ResponseWriter, r *http.Request, redirectURI, code, description string) {
	location, err := url.Parse(redirectURI)
	if err != nil {
		writeError(w, http.StatusBadRequest, description)
		return
	}
	values := location.Query()
	values.Set("error", code)
	if description != "" {
		values.Set("error_description", description)
	}
	if state := r.URL.Query().Get("state"); state != "" {
		values.Set("state", state)
	}
	location.RawQuery = values.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) oidcClientByID(clientID string) (model.PlatformItem, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return model.PlatformItem{}, errors.New("client_id is required")
	}
	items, err := s.cfg.Store.ListPlatformItems("oidc_clients")
	if err != nil {
		return model.PlatformItem{}, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		if oidcClientID(item) != clientID {
			continue
		}
		raw, ok, err := s.cfg.Store.GetPlatformItem("oidc_clients", item.ID)
		if err != nil {
			return model.PlatformItem{}, err
		}
		if !ok {
			return model.PlatformItem{}, errors.New("oidc client not found")
		}
		return raw, nil
	}
	return model.PlatformItem{}, errors.New("oidc client not found")
}

func oidcClientCredentialsFromRequest(r *http.Request) oidcClientCredentials {
	clientID, clientSecret, _ := r.BasicAuth()
	if clientID == "" {
		clientID = r.PostForm.Get("client_id")
	}
	if clientSecret == "" {
		clientSecret = r.PostForm.Get("client_secret")
	}
	return oidcClientCredentials{
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: clientSecret,
	}
}

func oidcClientID(item model.PlatformItem) string {
	if value := firstMetadataString(item.Metadata, "client_id", "clientId"); value != "" {
		return value
	}
	if item.Name != "" {
		return item.Name
	}
	return item.ID
}

func oidcRedirectAllowed(item model.PlatformItem, redirectURI string) bool {
	redirectURI = strings.TrimSpace(redirectURI)
	if redirectURI == "" {
		return false
	}
	for _, candidate := range oidcRedirectURIs(item) {
		if strings.TrimSpace(candidate) == redirectURI {
			return true
		}
	}
	return false
}

func oidcRedirectURIs(item model.PlatformItem) []string {
	values := []string{}
	for _, key := range []string{"redirect_uris", "redirectUris", "redirect_uri", "redirectUri", "callbacks", "callback_urls"} {
		for _, value := range metadataStrings(item.Metadata[key]) {
			values = append(values, splitCriteria(value)...)
		}
	}
	if item.Host != "" {
		values = append(values, item.Host)
	}
	return values
}

func oidcValidateScope(item model.PlatformItem, requested string) (string, error) {
	requestedScopes := strings.Fields(strings.TrimSpace(requested))
	if len(requestedScopes) == 0 {
		requestedScopes = []string{"openid"}
	}
	allowed := map[string]bool{}
	allowedScopes := metadataStrings(item.Metadata["scopes"])
	if len(allowedScopes) == 0 {
		allowedScopes = []string{"openid", "profile", "email"}
	}
	for _, value := range allowedScopes {
		for _, scope := range strings.Fields(strings.ReplaceAll(value, ",", " ")) {
			allowed[strings.TrimSpace(scope)] = true
		}
	}
	hasOpenID := false
	for _, scope := range requestedScopes {
		if scope == "openid" {
			hasOpenID = true
		}
		if !allowed[scope] {
			return "", errors.New("scope is not allowed: " + scope)
		}
	}
	if !hasOpenID {
		return "", errors.New("openid scope is required")
	}
	return strings.Join(requestedScopes, " "), nil
}

func oidcClientSecretValid(item model.PlatformItem, secret string) bool {
	hash, _ := item.Metadata["client_secret_hash"].(string)
	if hash == "" {
		return strings.TrimSpace(secret) == "" && oidcClientAllowsPublicTokenAuth(item)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
}

func oidcClientRequiresPKCE(item model.PlatformItem) bool {
	return oidcClientAllowsPublicTokenAuth(item)
}

func oidcClientAllowsPublicTokenAuth(item model.PlatformItem) bool {
	method := strings.ToLower(firstMetadataString(item.Metadata, "token_endpoint_auth_method", "auth_method", "authMethod"))
	clientType := strings.ToLower(strings.TrimSpace(item.Type))
	return clientType == "public" || method == "none"
}

func (m *oidcManager) createAuthorizationCode(code oidcAuthorizationCode) (string, error) {
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLocked(); err != nil {
		return "", err
	}
	if m.store == nil {
		m.codes[token] = code
		return token, nil
	}
	if err := m.saveRuntimeRecord("oidc_authorization_codes", oidcRuntimeTokenID(token), code, code.ExpiresAt); err != nil {
		return "", err
	}
	return token, nil
}

func (m *oidcManager) consumeAuthorizationCode(codeValue, clientID, redirectURI, verifier string) (oidcAuthorizationCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLocked(); err != nil {
		return oidcAuthorizationCode{}, err
	}
	var code oidcAuthorizationCode
	var ok bool
	if m.store == nil {
		code, ok = m.codes[codeValue]
		delete(m.codes, codeValue)
	} else {
		item, found, err := m.store.GetPlatformItem("oidc_authorization_codes", oidcRuntimeTokenID(codeValue))
		if err != nil {
			return oidcAuthorizationCode{}, err
		}
		ok = found
		if found {
			if err := decodeOIDCRuntimePayload(item, &code); err != nil {
				return oidcAuthorizationCode{}, err
			}
			if err := m.store.DeletePlatformItem("oidc_authorization_codes", item.ID); err != nil {
				return oidcAuthorizationCode{}, err
			}
		}
	}
	if !ok {
		return oidcAuthorizationCode{}, errors.New("authorization code is invalid or already used")
	}
	if time.Now().UTC().After(code.ExpiresAt) {
		return oidcAuthorizationCode{}, errors.New("authorization code expired")
	}
	if code.ClientID != clientID || code.RedirectURI != redirectURI {
		return oidcAuthorizationCode{}, errors.New("authorization code does not match client or redirect_uri")
	}
	if !oidcPKCEValid(code, verifier) {
		return oidcAuthorizationCode{}, errors.New("code_verifier is invalid")
	}
	return code, nil
}

func (m *oidcManager) restoreAuthorizationCode(codeValue string, code oidcAuthorizationCode) error {
	codeValue = strings.TrimSpace(codeValue)
	if codeValue == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLocked(); err != nil {
		return err
	}
	if time.Now().UTC().After(code.ExpiresAt) {
		return nil
	}
	if m.store == nil {
		if _, exists := m.codes[codeValue]; !exists {
			m.codes[codeValue] = code
		}
		return nil
	}
	return m.saveRuntimeRecord("oidc_authorization_codes", oidcRuntimeTokenID(codeValue), code, code.ExpiresAt)
}

func (m *oidcManager) createAccessToken(token oidcAccessToken) (string, error) {
	value, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLocked(); err != nil {
		return "", err
	}
	if m.store == nil {
		m.accessTokens[value] = token
		return value, nil
	}
	if err := m.saveRuntimeRecord("oidc_access_tokens", oidcRuntimeTokenID(value), token, token.ExpiresAt); err != nil {
		return "", err
	}
	return value, nil
}

func (m *oidcManager) accessToken(value string) (oidcAccessToken, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.pruneLocked(); err != nil {
		return oidcAccessToken{}, false, err
	}
	if m.store == nil {
		token, ok := m.accessTokens[value]
		return token, ok, nil
	}
	item, ok, err := m.store.GetPlatformItem("oidc_access_tokens", oidcRuntimeTokenID(value))
	if err != nil || !ok {
		return oidcAccessToken{}, ok, err
	}
	var token oidcAccessToken
	if err := decodeOIDCRuntimePayload(item, &token); err != nil {
		return oidcAccessToken{}, false, err
	}
	return token, true, nil
}

func (m *oidcManager) pruneLocked() error {
	now := time.Now().UTC()
	if m.store != nil {
		for _, collection := range []string{"oidc_authorization_codes", "oidc_access_tokens"} {
			items, err := m.store.ListPlatformItems(collection)
			if err != nil {
				return err
			}
			for _, item := range items {
				expiresAt, ok := metadataTime(item.Metadata["expires_at"])
				if ok && !now.Before(expiresAt) {
					if err := m.store.DeletePlatformItem(collection, item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
						return err
					}
				}
			}
		}
		return nil
	}
	for key, code := range m.codes {
		if now.After(code.ExpiresAt) {
			delete(m.codes, key)
		}
	}
	for key, token := range m.accessTokens {
		if now.After(token.ExpiresAt) {
			delete(m.accessTokens, key)
		}
	}
	return nil
}

func oidcRuntimeTokenID(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (m *oidcManager) saveRuntimeRecord(collection, id string, payload any, expiresAt time.Time) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = m.store.SavePlatformItem(collection, model.PlatformItem{
		ID: id, Name: collection, Type: "oidc-runtime", Status: "active",
		Metadata: map[string]any{"payload": string(encoded), "expires_at": expiresAt.UTC().Format(time.RFC3339Nano)},
	})
	return err
}

func decodeOIDCRuntimePayload(item model.PlatformItem, target any) error {
	payload := firstMetadataString(item.Metadata, "payload")
	if payload == "" {
		return errors.New("persisted OIDC runtime record is missing payload")
	}
	if err := json.Unmarshal([]byte(payload), target); err != nil {
		return fmt.Errorf("decode persisted OIDC runtime record: %w", err)
	}
	return nil
}

func oidcPKCEValid(code oidcAuthorizationCode, verifier string) bool {
	if code.CodeChallenge == "" {
		return true
	}
	if !oidcPKCEValueValid(verifier) {
		return false
	}
	switch code.CodeChallengeMethod {
	case "S256":
		sum := sha256.Sum256([]byte(verifier))
		return base64.RawURLEncoding.EncodeToString(sum[:]) == code.CodeChallenge
	default:
		return verifier == code.CodeChallenge
	}
}

func oidcPKCEValueValid(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, ch := range value {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' || ch == '_' || ch == '~' {
			continue
		}
		return false
	}
	return true
}

func (m *oidcManager) signIDToken(issuer string, code oidcAuthorizationCode) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":                issuer,
		"sub":                code.UserID,
		"aud":                code.ClientID,
		"exp":                now.Add(oidcAccessTokenTTL).Unix(),
		"iat":                now.Unix(),
		"name":               code.Username,
		"preferred_username": code.Username,
		"role":               code.Role,
	}
	if !code.AuthTime.IsZero() {
		claims["auth_time"] = code.AuthTime.UTC().Unix()
	}
	if code.Nonce != "" {
		claims["nonce"] = code.Nonce
	}
	return m.signJWT(claims)
}

func (m *oidcManager) signJWT(claims map[string]any) (string, error) {
	header := map[string]any{"typ": "JWT", "alg": "RS256", "kid": m.keyID}
	headerRaw, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsRaw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(claimsRaw)
	sum := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, m.privateKey, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func requestBaseURL(r *http.Request, trustProxy bool) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if trustProxy {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwarded == "http" || forwarded == "https" {
			scheme = forwarded
		}
	}
	return scheme + "://" + effectiveHost(r, trustProxy)
}
