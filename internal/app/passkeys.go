package app

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"

	"github.com/fxamacker/cbor/v2"
)

type passkeyChallenge struct {
	User       store.AdminPublic
	Username   string
	Challenge  string
	RPID       string
	Origin     string
	ClientIP   string
	FailureKey string
	ExpiresAt  time.Time
}

type passkeyRegisterVerifyRequest struct {
	ChallengeID string                  `json:"challenge_id"`
	Name        string                  `json:"name"`
	ID          string                  `json:"id"`
	RawID       string                  `json:"raw_id"`
	Type        string                  `json:"type"`
	Response    passkeyAttestationReply `json:"response"`
}

type passkeyAttestationReply struct {
	ClientDataJSON    string `json:"client_data_json"`
	AttestationObject string `json:"attestation_object"`
}

type passkeyLoginOptionsRequest struct {
	Username string `json:"username"`
}

type passkeyLoginVerifyRequest struct {
	ChallengeID string                `json:"challenge_id"`
	ID          string                `json:"id"`
	RawID       string                `json:"raw_id"`
	Type        string                `json:"type"`
	Response    passkeyAssertionReply `json:"response"`
}

type passkeyAssertionReply struct {
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
	UserHandle        string `json:"user_handle"`
}

type passkeyOptionsResponse struct {
	ChallengeID string `json:"challenge_id"`
	PublicKey   any    `json:"publicKey"`
}

type passkeyCreationOptions struct {
	Challenge              string                        `json:"challenge"`
	RP                     passkeyRelyingParty           `json:"rp"`
	User                   passkeyUserEntity             `json:"user"`
	PubKeyCredParams       []passkeyCredentialParameter  `json:"pubKeyCredParams"`
	Timeout                int                           `json:"timeout"`
	AuthenticatorSelection passkeyAuthenticatorSelection `json:"authenticatorSelection"`
	Attestation            string                        `json:"attestation"`
	ExcludeCredentials     []passkeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
}

type passkeyRequestOptions struct {
	Challenge        string                        `json:"challenge"`
	Timeout          int                           `json:"timeout"`
	RPID             string                        `json:"rpId"`
	AllowCredentials []passkeyCredentialDescriptor `json:"allowCredentials"`
	UserVerification string                        `json:"userVerification"`
}

type passkeyRelyingParty struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type passkeyUserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type passkeyCredentialParameter struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type passkeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type passkeyAuthenticatorSelection struct {
	ResidentKey      string `json:"residentKey"`
	UserVerification string `json:"userVerification"`
}

type passkeyPublicItem struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	CredentialID string    `json:"credential_id"`
	SignCount    int       `json:"sign_count"`
	LastUsedAt   string    `json:"last_used_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type webauthnClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin,omitempty"`
}

type passkeyAttestationObject struct {
	AuthData []byte `cbor:"authData"`
}

type passkeyEC2PublicKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint"`
	Crv int    `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint"`
}

type passkeyRegistrationData struct {
	CredentialID []byte
	PublicKey    passkeyEC2PublicKey
	SignCount    uint32
	AAGUID       []byte
	Flags        byte
}

func (s *Server) handleAuthenticatedPasskeys(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/auth/passkeys":
		s.handlePasskeyList(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/passkeys/register/options":
		s.handlePasskeyRegisterOptions(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/passkeys/register/verify":
		s.handlePasskeyRegisterVerify(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/api/auth/passkeys/"):
		s.handlePasskeyDelete(w, r)
	default:
		writeError(w, http.StatusNotFound, "passkey endpoint not found")
	}
}

func (s *Server) handlePasskeyLoginAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/passkeys/login/options":
		s.handlePasskeyLoginOptions(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/api/auth/passkeys/login/verify":
		s.handlePasskeyLoginVerify(w, r)
	default:
		writeError(w, http.StatusNotFound, "passkey endpoint not found")
	}
}

func (s *Server) handlePasskeyList(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	items, err := s.passkeysForUser(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]passkeyPublicItem, 0, len(items))
	for _, item := range items {
		out = append(out, publicPasskeyItem(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handlePasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	challenge, err := randomPasskeyChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rpID := requestRPID(r, s.cfg.TrustProxyHeaders)
	origin := requestOrigin(r, s.cfg.TrustProxyHeaders)
	existing, err := s.passkeysForUser(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	exclude := make([]passkeyCredentialDescriptor, 0, len(existing))
	for _, item := range existing {
		if credentialID := passkeyCredentialID(item); credentialID != "" {
			exclude = append(exclude, passkeyCredentialDescriptor{Type: "public-key", ID: credentialID})
		}
	}
	token, err := s.auth.createPasskeyRegistrationChallenge(passkeyChallenge{
		User:      store.AdminPublic{UserID: session.UserID, Username: session.Username, Role: session.Role},
		Username:  session.Username,
		Challenge: challenge,
		RPID:      rpID,
		Origin:    origin,
		ClientIP:  s.clientIP(r),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	options := passkeyCreationOptions{
		Challenge: challenge,
		RP:        passkeyRelyingParty{Name: s.passkeyRPName(), ID: rpID},
		User: passkeyUserEntity{
			ID:          passkeyBase64Encode([]byte(session.UserID)),
			Name:        session.Username,
			DisplayName: session.Username,
		},
		PubKeyCredParams: []passkeyCredentialParameter{{Type: "public-key", Alg: -7}},
		Timeout:          60000,
		AuthenticatorSelection: passkeyAuthenticatorSelection{
			ResidentKey:      "preferred",
			UserVerification: "preferred",
		},
		Attestation:        "none",
		ExcludeCredentials: exclude,
	}
	writeJSON(w, http.StatusOK, passkeyOptionsResponse{ChallengeID: token, PublicKey: options})
}

func (s *Server) handlePasskeyRegisterVerify(w http.ResponseWriter, r *http.Request) {
	var req passkeyRegisterVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	_, session, _ := s.authSession(r)
	challengeID := strings.TrimSpace(req.ChallengeID)
	challenge, ok := s.auth.passkeyRegistrationChallenge(challengeID)
	if challengeID == "" || !ok || challenge.User.UserID != session.UserID {
		writeError(w, http.StatusUnauthorized, "passkey registration challenge expired")
		return
	}
	defer s.auth.deletePasskeyRegistrationChallenge(challengeID)
	if strings.TrimSpace(req.Type) != "" && req.Type != "public-key" {
		writeError(w, http.StatusBadRequest, "unsupported passkey credential type")
		return
	}
	clientDataJSON, err := passkeyBase64Decode(req.Response.ClientDataJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid client data")
		return
	}
	if err := validateWebAuthnClientData(clientDataJSON, "webauthn.create", challenge.Challenge, challenge.Origin); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	attestationObject, err := passkeyBase64Decode(req.Response.AttestationObject)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid attestation object")
		return
	}
	data, err := parsePasskeyAttestation(attestationObject, challenge.RPID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	rawID, err := passkeyRequestCredentialID(req.RawID, req.ID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(rawID) > 0 && !bytes.Equal(rawID, data.CredentialID) {
		writeError(w, http.StatusBadRequest, "credential id does not match attestation data")
		return
	}
	credentialID := passkeyBase64Encode(data.CredentialID)
	if _, _, ok, err := s.passkeyByCredentialID("", credentialID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	} else if ok {
		writeError(w, http.StatusConflict, "passkey already registered")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey"
	}
	item, err := s.cfg.Store.CreatePlatformItem("passkeys", model.PlatformItemRequest{
		Name:     name,
		Type:     "public-key",
		Status:   "enabled",
		OwnerID:  session.UserID,
		Username: session.Username,
		Metadata: map[string]any{
			"credential_id": credentialID,
			"public_key_x":  passkeyBase64Encode(data.PublicKey.X),
			"public_key_y":  passkeyBase64Encode(data.PublicKey.Y),
			"sign_count":    int(data.SignCount),
			"rp_id":         challenge.RPID,
			"aaguid":        passkeyBase64Encode(data.AAGUID),
			"flags":         int(data.Flags),
			"created_ip":    challenge.ClientIP,
			"user_agent":    trimMetadataTextForPasskey(r.UserAgent(), 512),
		},
		Description: "Browser passkey credential for passwordless login.",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createPasskeyOperationLog(r, "auth.passkey.register", "success", item.ID, session.UserID, "registered passkey", map[string]any{
		"credential_id": credentialID,
	}); err != nil {
		_ = s.cfg.Store.DeletePlatformItem("passkeys", item.ID)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.passkey.register", item.ID, "", "registered passkey")
	writeJSON(w, http.StatusCreated, publicPasskeyItem(item))
}

func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/passkeys/"), "/")
	if id == "" {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("passkeys", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok || item.OwnerID != session.UserID {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}
	previous := item
	previous.Metadata = cloneMetadata(item.Metadata)
	if err := s.cfg.Store.DeletePlatformItem("passkeys", id); err != nil {
		writeError(w, http.StatusNotFound, "passkey not found")
		return
	}
	if err := s.createPasskeyOperationLog(r, "auth.passkey.delete", "success", id, session.UserID, "deleted passkey", nil); err != nil {
		_, _ = s.cfg.Store.SavePlatformItem("passkeys", previous)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.passkey.delete", id, "", "deleted passkey")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) createPasskeyOperationLog(r *http.Request, name, status, id, userID, description string, metadata map[string]any) error {
	if metadata == nil {
		metadata = map[string]any{}
	} else {
		metadata = cloneMetadata(metadata)
	}
	metadata["client_ip"] = s.clientIP(r)
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        name,
		Type:        "passkey",
		Status:      status,
		OwnerID:     userID,
		TargetID:    id,
		Description: description,
		Metadata:    metadata,
	})
}

func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginOptionsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.cfg.Store.AdminConfigured() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":          "admin setup required",
			"setup_required": true,
		})
		return
	}
	username := strings.TrimSpace(req.Username)
	clientIP := s.clientIP(r)
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}
	if ok, reason := s.loginPolicyAllows(username, clientIP); !ok {
		if err := s.createLoginLog(r, model.PlatformItemRequest{
			Name:        username,
			Type:        "passkey",
			Status:      "denied",
			Description: reason,
			Metadata:    map[string]any{"client_ip": clientIP, "account": username},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeError(w, http.StatusForbidden, reason)
		return
	}
	if retryAfter, locked := s.activeLoginLock(username, clientIP); locked {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "account or client ip is locked; try again later")
		return
	}
	failureKey := clientIP + ":" + strings.ToLower(username)
	failurePolicy := s.loginFailurePolicy()
	if retryAfter, ok := s.auth.checkLoginAllowed(failureKey, failurePolicy); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retryAfter.Seconds())))
		writeError(w, http.StatusTooManyRequests, "too many failed login attempts; try again later")
		return
	}
	user, ok, err := s.passkeyUserByUsername(username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		s.recordPasskeyLoginFailure(w, r, username, clientIP, failureKey, "passkey is not available for this account")
		return
	}
	items, err := s.passkeysForUser(user.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	allow := make([]passkeyCredentialDescriptor, 0, len(items))
	for _, item := range items {
		if credentialID := passkeyCredentialID(item); credentialID != "" {
			allow = append(allow, passkeyCredentialDescriptor{Type: "public-key", ID: credentialID})
		}
	}
	if len(allow) == 0 {
		s.recordPasskeyLoginFailure(w, r, username, clientIP, failureKey, "passkey is not available for this account")
		return
	}
	challenge, err := randomPasskeyChallenge()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	token, err := s.auth.createPasskeyLoginChallenge(passkeyChallenge{
		User:       user,
		Username:   username,
		Challenge:  challenge,
		RPID:       requestRPID(r, s.cfg.TrustProxyHeaders),
		Origin:     requestOrigin(r, s.cfg.TrustProxyHeaders),
		ClientIP:   clientIP,
		FailureKey: failureKey,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	options := passkeyRequestOptions{
		Challenge:        challenge,
		Timeout:          60000,
		RPID:             requestRPID(r, s.cfg.TrustProxyHeaders),
		AllowCredentials: allow,
		UserVerification: "preferred",
	}
	writeJSON(w, http.StatusOK, passkeyOptionsResponse{ChallengeID: token, PublicKey: options})
}

func (s *Server) handlePasskeyLoginVerify(w http.ResponseWriter, r *http.Request) {
	var req passkeyLoginVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	challengeID := strings.TrimSpace(req.ChallengeID)
	challenge, ok := s.auth.passkeyLoginChallenge(challengeID)
	if challengeID == "" || !ok {
		writeError(w, http.StatusUnauthorized, "passkey login challenge expired")
		return
	}
	defer s.auth.deletePasskeyLoginChallenge(challengeID)
	currentUser, ok, err := s.passkeyUserByID(challenge.User.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "passkey account is disabled or no longer exists")
		return
	}
	challenge.User = currentUser
	clientDataJSON, err := passkeyBase64Decode(req.Response.ClientDataJSON)
	if err != nil {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid passkey client data")
		return
	}
	if err := validateWebAuthnClientData(clientDataJSON, "webauthn.get", challenge.Challenge, challenge.Origin); err != nil {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, err.Error())
		return
	}
	rawID, err := passkeyRequestCredentialID(req.RawID, req.ID)
	if err != nil || len(rawID) == 0 {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid passkey credential id")
		return
	}
	credentialID := passkeyBase64Encode(rawID)
	item, publicKey, ok, err := s.passkeyByCredentialID(challenge.User.UserID, credentialID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "passkey credential is not registered")
		return
	}
	authenticatorData, err := passkeyBase64Decode(req.Response.AuthenticatorData)
	if err != nil {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid authenticator data")
		return
	}
	signCount, err := validatePasskeyAssertionAuthData(authenticatorData, challenge.RPID)
	if err != nil {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, err.Error())
		return
	}
	signature, err := passkeyBase64Decode(req.Response.Signature)
	if err != nil {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid passkey signature")
		return
	}
	if !verifyPasskeySignature(publicKey, authenticatorData, clientDataJSON, signature) {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "invalid passkey signature")
		return
	}
	storedSignCount := passkeyMetadataInt(item.Metadata["sign_count"])
	if storedSignCount > 0 && signCount > 0 && int(signCount) <= storedSignCount {
		s.recordPasskeyLoginFailure(w, r, challenge.Username, challenge.ClientIP, challenge.FailureKey, "passkey sign count did not advance")
		return
	}
	if item.Metadata == nil {
		item.Metadata = map[string]any{}
	}
	if signCount > 0 {
		item.Metadata["sign_count"] = int(signCount)
	}
	item.Metadata["last_used_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	item.Metadata["last_used_ip"] = challenge.ClientIP
	if _, err := s.cfg.Store.SavePlatformItem("passkeys", item); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.auth.resetLoginFailures(challenge.FailureKey)
	token, session, err := s.auth.create(challenge.User)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.cfg.Store.RecordUserLogin(session.UserID, challenge.ClientIP, r.UserAgent())
	_ = s.audit(r, "auth.passkey.login", session.UserID, "", "signed in with passkey")
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        challenge.Username,
		Type:        "passkey",
		Status:      "success",
		OwnerID:     session.UserID,
		Description: "signed in with passkey",
		Metadata: map[string]any{
			"client_ip":     challenge.ClientIP,
			"account":       challenge.Username,
			"credential_id": credentialID,
			"passkey_id":    item.ID,
			"user_agent":    trimMetadataTextForPasskey(r.UserAgent(), 512),
		},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	http.SetCookie(w, s.authCookie(r, token, int(authSessionTTL.Seconds())))
	writeJSON(w, http.StatusOK, map[string]any{"user": s.authUserPayload(session)})
}

func (s *Server) recordPasskeyLoginFailure(w http.ResponseWriter, r *http.Request, username, clientIP, failureKey, detail string) {
	failure := s.auth.recordLoginFailure(failureKey, s.loginFailurePolicy())
	if !failure.LockedUntil.IsZero() {
		if err := s.createLoginLock(username, clientIP, failure); err != nil {
			lockDetail := "persist login lock failed: " + err.Error()
			_ = s.audit(r, "auth.login.lock.persist_failed", "", "", lockDetail)
			writeError(w, http.StatusInternalServerError, lockDetail)
			return
		}
	}
	if err := s.createLoginLog(r, model.PlatformItemRequest{
		Name:        username,
		Type:        "passkey",
		Status:      "failed",
		Description: detail,
		Metadata:    map[string]any{"client_ip": clientIP, "account": username},
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.passkey.login_failed", "", "", detail)
	writeError(w, http.StatusUnauthorized, detail)
}

func (s *Server) passkeysForUser(userID string) ([]model.PlatformItem, error) {
	items, err := s.cfg.Store.ListPlatformItems("passkeys")
	if err != nil {
		return nil, err
	}
	result := []model.PlatformItem{}
	for _, item := range items {
		if item.OwnerID == userID && platformItemEnabled(item) {
			result = append(result, item)
		}
	}
	return result, nil
}

func (s *Server) passkeyByCredentialID(userID, credentialID string) (model.PlatformItem, *ecdsa.PublicKey, bool, error) {
	items, err := s.cfg.Store.ListPlatformItems("passkeys")
	if err != nil {
		return model.PlatformItem{}, nil, false, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) || passkeyCredentialID(item) != credentialID {
			continue
		}
		if userID != "" && item.OwnerID != userID {
			continue
		}
		raw, ok, err := s.cfg.Store.GetPlatformItem("passkeys", item.ID)
		if err != nil || !ok {
			return model.PlatformItem{}, nil, false, err
		}
		publicKey, err := passkeyPublicKeyFromMetadata(raw.Metadata)
		if err != nil {
			return model.PlatformItem{}, nil, false, err
		}
		return raw, publicKey, true, nil
	}
	return model.PlatformItem{}, nil, false, nil
}

func (s *Server) passkeyUserByUsername(username string) (store.AdminPublic, bool, error) {
	items, err := s.cfg.Store.ListPlatformItems("users")
	if err != nil {
		return store.AdminPublic{}, false, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) || strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			continue
		}
		if !strings.EqualFold(item.Name, username) && !strings.EqualFold(item.Username, username) {
			continue
		}
		return passkeyAuthUserFromItem(item), true, nil
	}
	return store.AdminPublic{}, false, nil
}

func (s *Server) passkeyUserByID(userID string) (store.AdminPublic, bool, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return store.AdminPublic{}, false, nil
	}
	item, ok, err := s.cfg.Store.GetPlatformItem("users", userID)
	if err != nil || !ok {
		return store.AdminPublic{}, false, err
	}
	if !platformItemEnabled(item) || strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
		return store.AdminPublic{}, false, nil
	}
	return passkeyAuthUserFromItem(item), true, nil
}

func passkeyAuthUserFromItem(item model.PlatformItem) store.AdminPublic {
	role := strings.TrimSpace(passkeyMetadataText(item.Metadata["role"]))
	if role == "" {
		role = "user"
	}
	return store.AdminPublic{
		UserID:    item.ID,
		Username:  item.Name,
		Role:      role,
		CreatedAt: item.CreatedAt,
		UpdatedAt: item.UpdatedAt,
	}
}

func publicPasskeyItem(item model.PlatformItem) passkeyPublicItem {
	return passkeyPublicItem{
		ID:           item.ID,
		Name:         item.Name,
		CredentialID: passkeyCredentialID(item),
		SignCount:    passkeyMetadataInt(item.Metadata["sign_count"]),
		LastUsedAt:   passkeyMetadataText(item.Metadata["last_used_at"]),
		CreatedAt:    item.CreatedAt,
		UpdatedAt:    item.UpdatedAt,
	}
}

func passkeyCredentialID(item model.PlatformItem) string {
	return passkeyMetadataText(item.Metadata["credential_id"])
}

func validateWebAuthnClientData(raw []byte, wantType, challenge, origin string) error {
	var data webauthnClientData
	if err := json.Unmarshal(raw, &data); err != nil {
		return errors.New("invalid webauthn client data")
	}
	if data.Type != wantType {
		return errors.New("unexpected webauthn client data type")
	}
	gotChallenge, err := passkeyBase64Decode(data.Challenge)
	if err != nil {
		return errors.New("invalid webauthn challenge")
	}
	wantChallenge, err := passkeyBase64Decode(challenge)
	if err != nil {
		return errors.New("invalid expected webauthn challenge")
	}
	if !bytes.Equal(gotChallenge, wantChallenge) {
		return errors.New("webauthn challenge mismatch")
	}
	if data.Origin != origin {
		return errors.New("webauthn origin mismatch")
	}
	if data.CrossOrigin {
		return errors.New("cross-origin webauthn requests are not allowed")
	}
	return nil
}

func parsePasskeyAttestation(raw []byte, rpID string) (passkeyRegistrationData, error) {
	var obj passkeyAttestationObject
	if err := cbor.Unmarshal(raw, &obj); err != nil {
		return passkeyRegistrationData{}, errors.New("invalid attestation object")
	}
	if len(obj.AuthData) == 0 {
		return passkeyRegistrationData{}, errors.New("attestation object missing auth data")
	}
	return parsePasskeyRegistrationAuthData(obj.AuthData, rpID)
}

func parsePasskeyRegistrationAuthData(authData []byte, rpID string) (passkeyRegistrationData, error) {
	if len(authData) < 37+16+2 {
		return passkeyRegistrationData{}, errors.New("authenticator data is too short")
	}
	if err := validatePasskeyRPHash(authData, rpID); err != nil {
		return passkeyRegistrationData{}, err
	}
	flags := authData[32]
	if flags&0x01 == 0 {
		return passkeyRegistrationData{}, errors.New("passkey user presence was not verified")
	}
	if flags&0x40 == 0 {
		return passkeyRegistrationData{}, errors.New("passkey attested credential data is missing")
	}
	signCount := binary.BigEndian.Uint32(authData[33:37])
	offset := 37
	aaguid := append([]byte{}, authData[offset:offset+16]...)
	offset += 16
	credentialLen := int(binary.BigEndian.Uint16(authData[offset : offset+2]))
	offset += 2
	if credentialLen <= 0 || len(authData) < offset+credentialLen {
		return passkeyRegistrationData{}, errors.New("invalid passkey credential id length")
	}
	credentialID := append([]byte{}, authData[offset:offset+credentialLen]...)
	offset += credentialLen
	var publicKey passkeyEC2PublicKey
	if err := cbor.Unmarshal(authData[offset:], &publicKey); err != nil {
		return passkeyRegistrationData{}, errors.New("invalid passkey cose public key")
	}
	if err := validatePasskeyEC2PublicKey(publicKey); err != nil {
		return passkeyRegistrationData{}, err
	}
	return passkeyRegistrationData{
		CredentialID: credentialID,
		PublicKey:    publicKey,
		SignCount:    signCount,
		AAGUID:       aaguid,
		Flags:        flags,
	}, nil
}

func validatePasskeyAssertionAuthData(authData []byte, rpID string) (uint32, error) {
	if len(authData) < 37 {
		return 0, errors.New("authenticator data is too short")
	}
	if err := validatePasskeyRPHash(authData, rpID); err != nil {
		return 0, err
	}
	if authData[32]&0x01 == 0 {
		return 0, errors.New("passkey user presence was not verified")
	}
	return binary.BigEndian.Uint32(authData[33:37]), nil
}

func validatePasskeyRPHash(authData []byte, rpID string) error {
	expected := sha256.Sum256([]byte(rpID))
	if len(authData) < len(expected) || !bytes.Equal(authData[:32], expected[:]) {
		return errors.New("passkey relying party id mismatch")
	}
	return nil
}

func validatePasskeyEC2PublicKey(key passkeyEC2PublicKey) error {
	if key.Kty != 2 || key.Alg != -7 || key.Crv != 1 {
		return errors.New("passkey public key must be ES256 P-256")
	}
	if len(key.X) != 32 || len(key.Y) != 32 {
		return errors.New("passkey public key coordinates are invalid")
	}
	if !elliptic.P256().IsOnCurve(new(big.Int).SetBytes(key.X), new(big.Int).SetBytes(key.Y)) {
		return errors.New("passkey public key is not on P-256")
	}
	return nil
}

func passkeyPublicKeyFromMetadata(metadata map[string]any) (*ecdsa.PublicKey, error) {
	xRaw, err := passkeyBase64Decode(passkeyMetadataText(metadata["public_key_x"]))
	if err != nil {
		return nil, errors.New("stored passkey public key is invalid")
	}
	yRaw, err := passkeyBase64Decode(passkeyMetadataText(metadata["public_key_y"]))
	if err != nil {
		return nil, errors.New("stored passkey public key is invalid")
	}
	key := passkeyEC2PublicKey{Kty: 2, Alg: -7, Crv: 1, X: xRaw, Y: yRaw}
	if err := validatePasskeyEC2PublicKey(key); err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xRaw),
		Y:     new(big.Int).SetBytes(yRaw),
	}, nil
}

func verifyPasskeySignature(publicKey *ecdsa.PublicKey, authenticatorData, clientDataJSON, signature []byte) bool {
	clientHash := sha256.Sum256(clientDataJSON)
	signed := make([]byte, 0, len(authenticatorData)+len(clientHash))
	signed = append(signed, authenticatorData...)
	signed = append(signed, clientHash[:]...)
	digest := sha256.Sum256(signed)
	return ecdsa.VerifyASN1(publicKey, digest[:], signature)
}

func passkeyRequestCredentialID(rawID, id string) ([]byte, error) {
	if strings.TrimSpace(rawID) != "" {
		return passkeyBase64Decode(rawID)
	}
	if strings.TrimSpace(id) != "" {
		return passkeyBase64Decode(id)
	}
	return nil, errors.New("credential id is required")
}

func randomPasskeyChallenge() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return passkeyBase64Encode(buf), nil
}

func passkeyBase64Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func passkeyBase64Decode(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty base64url value")
	}
	if raw, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	if raw, err := base64.URLEncoding.DecodeString(value); err == nil {
		return raw, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func requestOrigin(r *http.Request, trustProxy bool) string {
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

func requestRPID(r *http.Request, trustProxy bool) string {
	host := effectiveHost(r, trustProxy)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return strings.Trim(strings.ToLower(parsedHost), "[]")
	}
	return strings.Trim(strings.ToLower(strings.TrimSuffix(host, ".")), "[]")
}

func (s *Server) passkeyRPName() string {
	name := strings.TrimSpace(s.cfg.Public.SiteName)
	if name == "" {
		name = "Open Web Server Manager"
	}
	return name
}

func passkeyMetadataText(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.Itoa(int(typed))
	case float64:
		return strconv.Itoa(int(typed))
	default:
		return ""
	}
}

func passkeyMetadataInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			return parsed
		}
	}
	return 0
}

func trimMetadataTextForPasskey(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit]
}
