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
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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
	Email               string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

type oidcAccessToken struct {
	ClientID  string
	Scope     string
	UserID    string
	ExpiresAt time.Time
}

type oidcClientCredentials struct {
	ClientID     string
	ClientSecret string
	Method       string
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
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "name", "preferred_username", "role", "email"},
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
	w.Header().Set("Cache-Control", "no-store")
	query := r.URL.Query()
	for _, key := range []string{"client_id", "redirect_uri"} {
		if len(query[key]) != 1 {
			writeError(w, http.StatusBadRequest, key+" must be provided exactly once")
			return
		}
	}
	if !oidcAuthorizeValueValid(query.Get("client_id"), 256) || !oidcAuthorizeValueValid(query.Get("redirect_uri"), 2048) {
		writeError(w, http.StatusBadRequest, "client_id or redirect_uri is invalid")
		return
	}
	client, err := s.oidcClientByID(query.Get("client_id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	redirectURI := query.Get("redirect_uri")
	if !oidcRedirectAllowed(client, redirectURI) {
		writeError(w, http.StatusBadRequest, "redirect_uri is not allowed for client")
		return
	}
	if err := validateOIDCAuthorizeParameters(query); err != nil {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", err.Error())
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
	if oidcClientRequiresPKCE(client) && codeChallengeMethod != "S256" {
		s.redirectOIDCError(w, r, redirectURI, "invalid_request", "public clients must use S256 PKCE")
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

func validateOIDCAuthorizeParameters(query url.Values) error {
	limits := map[string]int{
		"response_type": 32, "response_mode": 16, "scope": 4096, "state": 2048,
		"nonce": 2048, "code_challenge": 128, "code_challenge_method": 16,
		"prompt": 128, "max_age": 32,
	}
	for key, limit := range limits {
		values := query[key]
		if len(values) > 1 {
			return fmt.Errorf("authorization parameter %s must not be repeated", key)
		}
		if len(values) == 1 && !oidcAuthorizeValueValid(values[0], limit) {
			return fmt.Errorf("authorization parameter %s is invalid or exceeds %d bytes", key, limit)
		}
	}
	return nil
}

func oidcAuthorizeValueValid(value string, limit int) bool {
	if len(value) > limit {
		return false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return false
		}
	}
	return true
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_request", "invalid token request")
		return
	}
	if err := validateOIDCTokenRequestParameters(r); err != nil {
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeOIDCTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
		return
	}
	credentials, err := oidcClientCredentialsFromRequest(r)
	if err != nil {
		writeOIDCTokenError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	client, err := s.oidcClientByID(credentials.ClientID)
	if err != nil {
		writeOIDCInvalidClient(w, credentials.Method == "client_secret_basic")
		return
	}
	if !oidcClientCredentialsValid(client, credentials) {
		writeOIDCInvalidClient(w, oidcClientAuthMethod(client) == "client_secret_basic")
		return
	}
	redirectURI := r.PostForm.Get("redirect_uri")
	codeValue := r.PostForm.Get("code")
	code, err := s.oidc.consumeAuthorizationCode(codeValue, oidcClientID(client), redirectURI, r.PostForm.Get("code_verifier"))
	if err != nil {
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}
	if !oidcRedirectAllowed(client, redirectURI) {
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code redirect_uri is no longer allowed")
		return
	}
	currentUser, ok, err := s.authUserByID(code.UserID)
	if err != nil {
		err = s.restoreOIDCAuthorizationCodeAfterFailure(r, codeValue, code, err)
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if !ok {
		writeOIDCTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code user is disabled or no longer exists")
		return
	}
	code.Username = currentUser.Username
	code.Role = currentUser.Role
	code.Email, err = s.oidcUserEmail(code.UserID)
	if err != nil {
		err = s.restoreOIDCAuthorizationCodeAfterFailure(r, codeValue, code, err)
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	issuer := requestBaseURL(r, s.cfg.TrustProxyHeaders)
	idToken, err := s.oidc.signIDToken(issuer, code)
	if err != nil {
		err = s.restoreOIDCAuthorizationCodeAfterFailure(r, codeValue, code, err)
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	accessToken, err := s.oidc.createAccessToken(oidcAccessToken{
		ClientID:  code.ClientID,
		Scope:     code.Scope,
		UserID:    code.UserID,
		ExpiresAt: time.Now().UTC().Add(oidcAccessTokenTTL),
	})
	if err != nil {
		err = s.restoreOIDCAuthorizationCodeAfterFailure(r, codeValue, code, err)
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	if err := s.createOperationLog(r, model.PlatformItemRequest{
		Name:        "oidc.token",
		Type:        "oidc",
		Status:      "success",
		OwnerID:     code.UserID,
		TargetID:    code.ClientID,
		Description: "issued oidc tokens",
		Metadata:    map[string]any{"client_ip": s.clientIP(r), "client_id": code.ClientID, "scope": code.Scope},
	}); err != nil {
		err = s.rollbackOIDCTokenIssuance(r, accessToken, codeValue, code, err)
		writeOIDCTokenError(w, http.StatusInternalServerError, "server_error", err.Error())
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

func validateOIDCTokenRequestParameters(r *http.Request) error {
	limits := map[string]int{
		"grant_type": 64, "code": 1024, "redirect_uri": 2048, "code_verifier": 128,
		"client_id": 256, "client_secret": 4096,
	}
	for key, limit := range limits {
		values := r.PostForm[key]
		if len(values) > 1 {
			return fmt.Errorf("token parameter %s must not be repeated", key)
		}
		if len(values) == 1 && len(values[0]) > limit {
			return fmt.Errorf("token parameter %s exceeds %d bytes", key, limit)
		}
	}
	return nil
}

func writeOIDCInvalidClient(w http.ResponseWriter, basic bool) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc-token"`)
	}
	writeOIDCTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
}

func writeOIDCTokenError(w http.ResponseWriter, status int, code, description string) {
	payload := map[string]any{"error": code}
	if strings.TrimSpace(description) != "" {
		payload["error_description"] = description
	}
	writeJSON(w, status, payload)
}

func (s *Server) restoreOIDCAuthorizationCodeAfterFailure(r *http.Request, codeValue string, code oidcAuthorizationCode, originalErr error) error {
	if restoreErr := s.oidc.restoreAuthorizationCode(codeValue, code); restoreErr != nil {
		detail := "failed to restore OIDC authorization code: " + restoreErr.Error()
		_ = s.audit(r, "oidc.token.restore_failed", code.ClientID, "", detail)
		return fmt.Errorf("%w; additionally %s", originalErr, detail)
	}
	return originalErr
}

func (s *Server) rollbackOIDCTokenIssuance(r *http.Request, accessToken, codeValue string, code oidcAuthorizationCode, originalErr error) error {
	var rollbackErrors []string
	if err := s.oidc.deleteAccessToken(accessToken); err != nil {
		rollbackErrors = append(rollbackErrors, "delete access token: "+err.Error())
	}
	if err := s.oidc.restoreAuthorizationCode(codeValue, code); err != nil {
		rollbackErrors = append(rollbackErrors, "restore authorization code: "+err.Error())
	}
	if len(rollbackErrors) == 0 {
		return originalErr
	}
	detail := "failed to roll back OIDC token issuance: " + strings.Join(rollbackErrors, "; ")
	_ = s.audit(r, "oidc.token.restore_failed", code.ClientID, "", detail)
	return fmt.Errorf("%w; additionally %s", originalErr, detail)
}

func (s *Server) handleOIDCUserInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
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
	claims := map[string]any{"sub": user.UserID}
	if oidcScopeContains(accessToken.Scope, "profile") {
		claims["name"] = user.Username
		claims["preferred_username"] = user.Username
		claims["role"] = user.Role
	}
	if oidcScopeContains(accessToken.Scope, "email") {
		email, err := s.oidcUserEmail(user.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if email != "" {
			claims["email"] = email
		}
	}
	writeJSON(w, http.StatusOK, claims)
}

func (s *Server) oidcUserEmail(userID string) (string, error) {
	item, ok, err := s.cfg.Store.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return "", err
	}
	return firstMetadataString(item.Metadata, "email", "mail"), nil
}

func oidcScopeContains(scope, expected string) bool {
	for _, value := range strings.Fields(scope) {
		if value == expected {
			return true
		}
	}
	return false
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
	stateValues := r.URL.Query()["state"]
	if len(stateValues) == 1 && stateValues[0] != "" && oidcAuthorizeValueValid(stateValues[0], 2048) {
		state := stateValues[0]
		values.Set("state", state)
	}
	location.RawQuery = values.Encode()
	http.Redirect(w, r, location.String(), http.StatusFound)
}

func (s *Server) oidcClientByID(clientID string) (model.PlatformItem, error) {
	if !oidcClientIdentifierValid(clientID) {
		return model.PlatformItem{}, errors.New("client_id is required")
	}
	items, err := s.cfg.Store.ListPlatformItems("oidc_clients")
	if err != nil {
		return model.PlatformItem{}, err
	}
	matchedID := ""
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		if oidcClientID(item) != clientID {
			continue
		}
		if matchedID != "" {
			return model.PlatformItem{}, errors.New("oidc client_id is ambiguous")
		}
		matchedID = item.ID
	}
	if matchedID == "" {
		return model.PlatformItem{}, errors.New("oidc client not found")
	}
	raw, ok, err := s.cfg.Store.GetPlatformItem("oidc_clients", matchedID)
	if err != nil {
		return model.PlatformItem{}, err
	}
	if !ok {
		return model.PlatformItem{}, errors.New("oidc client not found")
	}
	if err := validateOIDCClientConfiguration(raw); err != nil {
		return model.PlatformItem{}, fmt.Errorf("oidc client configuration is invalid: %w", err)
	}
	if oidcClientAuthMethod(raw) != "none" && firstMetadataString(raw.Metadata, "client_secret_hash") == "" {
		return model.PlatformItem{}, errors.New("oidc client configuration is invalid: confidential client secret is not configured")
	}
	return raw, nil
}

func (s *Server) validateOIDCClientMutation(id string, existing *model.PlatformItem, req model.PlatformItemRequest) error {
	item := model.PlatformItem{
		Name:     strings.TrimSpace(req.Name),
		Type:     strings.TrimSpace(req.Type),
		Status:   strings.TrimSpace(req.Status),
		Host:     strings.TrimSpace(req.Host),
		Metadata: cloneMetadata(req.Metadata),
	}
	if existing != nil {
		item = platformItemAfterUpdate(*existing, req)
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	clientID := oidcClientID(item)
	if err := validateOIDCClientConfiguration(item); err != nil {
		return err
	}
	items, err := s.cfg.Store.ListPlatformItems("oidc_clients")
	if err != nil {
		return err
	}
	for _, candidate := range items {
		if candidate.ID != id && oidcClientID(candidate) == clientID {
			return errors.New("OIDC client_id is already in use")
		}
	}
	return nil
}

func validateOIDCClientConfiguration(item model.PlatformItem) error {
	clientID := oidcClientID(item)
	if !oidcClientIdentifierValid(clientID) {
		return errors.New("OIDC client_id must be 1-256 visible characters without whitespace or controls")
	}
	clientType := strings.ToLower(strings.TrimSpace(item.Type))
	if clientType == "" {
		clientType = "confidential"
	}
	if clientType != "confidential" && clientType != "public" {
		return errors.New("OIDC client type must be confidential or public")
	}
	authMethod := oidcClientAuthMethod(item)
	if clientType == "public" && authMethod != "none" {
		return errors.New("public OIDC clients must use token_endpoint_auth_method none")
	}
	if clientType == "confidential" && authMethod != "client_secret_basic" && authMethod != "client_secret_post" {
		return errors.New("confidential OIDC clients must use client_secret_basic or client_secret_post")
	}

	redirectURIs := oidcRedirectURIs(item)
	if len(redirectURIs) == 0 || len(redirectURIs) > 64 {
		return errors.New("OIDC clients must configure between 1 and 64 redirect URIs")
	}
	seenRedirects := map[string]bool{}
	for _, redirectURI := range redirectURIs {
		if strings.TrimSpace(redirectURI) != redirectURI {
			return errors.New("OIDC redirect URIs must not contain surrounding whitespace")
		}
		if seenRedirects[redirectURI] {
			return errors.New("OIDC redirect URIs must be unique")
		}
		seenRedirects[redirectURI] = true
		if err := validateOIDCRedirectURI(redirectURI, clientType == "public"); err != nil {
			return err
		}
	}
	if err := validateOIDCConfiguredScopes(item); err != nil {
		return err
	}
	return nil
}

func oidcClientIdentifierValid(value string) bool {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) || unicode.IsSpace(ch) {
			return false
		}
	}
	return true
}

func validateOIDCRedirectURI(raw string, publicClient bool) error {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return errors.New("OIDC redirect URI must be 1-2048 characters without controls")
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return fmt.Errorf("OIDC redirect URI %q must be absolute", raw)
	}
	if parsed.Fragment != "" {
		return fmt.Errorf("OIDC redirect URI %q must not include a fragment", raw)
	}
	if parsed.User != nil {
		return fmt.Errorf("OIDC redirect URI %q must not include user information", raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
		if parsed.Host == "" || parsed.Hostname() == "" {
			return fmt.Errorf("OIDC redirect URI %q must include a host", raw)
		}
	case "http":
		if parsed.Host == "" || !oidcLoopbackHost(parsed.Hostname()) {
			return fmt.Errorf("OIDC http redirect URI %q must use a loopback host", raw)
		}
	default:
		if !publicClient {
			return fmt.Errorf("OIDC redirect URI %q must use https or loopback http", raw)
		}
		if !oidcPrivateUseSchemeValid(scheme) || parsed.Host != "" {
			return fmt.Errorf("OIDC private-use redirect URI %q must use a reverse-domain scheme without a host", raw)
		}
		if parsed.Path == "" && parsed.Opaque == "" {
			return fmt.Errorf("OIDC private-use redirect URI %q must include a path", raw)
		}
	}
	return nil
}

func oidcLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func oidcPrivateUseSchemeValid(scheme string) bool {
	if len(scheme) > 255 {
		return false
	}
	labels := strings.Split(strings.ToLower(scheme), ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !oidcSchemeAlphaNumeric(label[0]) || !oidcSchemeAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for _, ch := range []byte(label) {
			if !oidcSchemeAlphaNumeric(ch) && ch != '-' {
				return false
			}
		}
	}
	return true
}

func oidcSchemeAlphaNumeric(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9'
}

func validateOIDCConfiguredScopes(item model.PlatformItem) error {
	values := metadataStrings(item.Metadata["scopes"])
	if len(values) == 0 {
		return errors.New("OIDC clients must configure 1-32 scopes including openid")
	}
	seen := map[string]bool{}
	count := 0
	hasOpenID := false
	for _, value := range values {
		for _, scope := range strings.Fields(strings.ReplaceAll(value, ",", " ")) {
			if !oidcScopeTokenValid(scope) {
				return fmt.Errorf("OIDC scope %q is invalid", scope)
			}
			if seen[scope] {
				return fmt.Errorf("OIDC scope %q is duplicated", scope)
			}
			seen[scope] = true
			count++
			hasOpenID = hasOpenID || scope == "openid"
		}
	}
	if count == 0 || count > 32 || !hasOpenID {
		return errors.New("OIDC clients must configure 1-32 scopes including openid")
	}
	return nil
}

func oidcScopeTokenValid(scope string) bool {
	if scope == "" || len(scope) > 128 {
		return false
	}
	for _, ch := range []byte(scope) {
		if ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\' {
			return false
		}
	}
	return true
}

func oidcClientCredentialsFromRequest(r *http.Request) (oidcClientCredentials, error) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if authorization != "" && !hasBasic {
		return oidcClientCredentials{}, errors.New("unsupported client authentication scheme")
	}
	bodyIDs, bodyHasID := r.PostForm["client_id"]
	bodySecrets, bodyHasSecret := r.PostForm["client_secret"]
	bodyID := ""
	if bodyHasID && len(bodyIDs) == 1 {
		bodyID = bodyIDs[0]
	}
	if hasBasic {
		if bodyHasSecret {
			return oidcClientCredentials{}, errors.New("multiple client authentication methods are not allowed")
		}
		if bodyHasID && bodyID != basicID {
			return oidcClientCredentials{}, errors.New("client_id does not match HTTP Basic credentials")
		}
		return oidcClientCredentials{ClientID: basicID, ClientSecret: basicSecret, Method: "client_secret_basic"}, nil
	}
	if bodyHasSecret {
		secret := ""
		if len(bodySecrets) == 1 {
			secret = bodySecrets[0]
		}
		return oidcClientCredentials{ClientID: bodyID, ClientSecret: secret, Method: "client_secret_post"}, nil
	}
	return oidcClientCredentials{ClientID: bodyID, Method: "none"}, nil
}

func oidcClientID(item model.PlatformItem) string {
	for _, key := range []string{"client_id", "clientId"} {
		values := metadataStrings(item.Metadata[key])
		if len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	if item.Name != "" {
		return item.Name
	}
	return item.ID
}

func oidcRedirectAllowed(item model.PlatformItem, redirectURI string) bool {
	if redirectURI == "" || strings.TrimSpace(redirectURI) != redirectURI {
		return false
	}
	for _, candidate := range oidcRedirectURIs(item) {
		if candidate == redirectURI {
			return true
		}
	}
	return false
}

func oidcRedirectURIs(item model.PlatformItem) []string {
	values := []string{}
	for _, key := range []string{"redirect_uris", "redirectUris", "redirect_uri", "redirectUri", "callbacks", "callback_urls"} {
		for _, raw := range metadataStrings(item.Metadata[key]) {
			normalized := strings.ReplaceAll(raw, "\r\n", "\n")
			lines := strings.Split(normalized, "\n")
			if len(lines) == 1 {
				values = append(values, raw)
				continue
			}
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					values = append(values, line)
				}
			}
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
	if len(requestedScopes) > 32 {
		return "", errors.New("no more than 32 scopes may be requested")
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
	seen := map[string]bool{}
	for _, scope := range requestedScopes {
		if !oidcScopeTokenValid(scope) {
			return "", errors.New("scope is invalid: " + scope)
		}
		if seen[scope] {
			return "", errors.New("scope is duplicated: " + scope)
		}
		seen[scope] = true
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

func oidcClientCredentialsValid(item model.PlatformItem, credentials oidcClientCredentials) bool {
	if credentials.Method != oidcClientAuthMethod(item) || len(credentials.ClientSecret) > 4096 {
		return false
	}
	hash, _ := item.Metadata["client_secret_hash"].(string)
	if hash == "" {
		return credentials.ClientSecret == "" && credentials.Method == "none" && oidcClientAllowsPublicTokenAuth(item)
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(credentials.ClientSecret)) == nil
}

func oidcClientRequiresPKCE(item model.PlatformItem) bool {
	return oidcClientAllowsPublicTokenAuth(item)
}

func oidcClientAllowsPublicTokenAuth(item model.PlatformItem) bool {
	return oidcClientAuthMethod(item) == "none"
}

func oidcClientAuthMethod(item model.PlatformItem) string {
	method := strings.ToLower(firstMetadataString(item.Metadata, "token_endpoint_auth_method", "auth_method", "authMethod"))
	if method != "" {
		return method
	}
	if strings.EqualFold(strings.TrimSpace(item.Type), "public") {
		return "none"
	}
	return "client_secret_basic"
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
	if !time.Now().UTC().Before(code.ExpiresAt) {
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
	if !time.Now().UTC().Before(code.ExpiresAt) {
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

func (m *oidcManager) deleteAccessToken(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.store == nil {
		delete(m.accessTokens, value)
		return nil
	}
	err := m.store.DeletePlatformItem("oidc_access_tokens", oidcRuntimeTokenID(value))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
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
		if !now.Before(code.ExpiresAt) {
			delete(m.codes, key)
		}
	}
	for key, token := range m.accessTokens {
		if !now.Before(token.ExpiresAt) {
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
		"iss": issuer,
		"sub": code.UserID,
		"aud": code.ClientID,
		"exp": now.Add(oidcAccessTokenTTL).Unix(),
		"iat": now.Unix(),
	}
	if oidcScopeContains(code.Scope, "profile") {
		claims["name"] = code.Username
		claims["preferred_username"] = code.Username
		claims["role"] = code.Role
	}
	if oidcScopeContains(code.Scope, "email") && code.Email != "" {
		claims["email"] = code.Email
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
