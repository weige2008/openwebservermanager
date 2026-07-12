package app

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"openwebservermanager/internal/model"
)

const sshPublicKeyCollection = "ssh_public_keys"

type sshPublicKeyRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
}

type sshPublicKeyItem struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Status      string    `json:"status"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	Comment     string    `json:"comment,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Server) handleAuthenticatedSSHPublicKeys(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimRight(r.URL.Path, "/")
	switch {
	case r.Method == http.MethodGet && path == "/api/auth/ssh-keys":
		s.handleSSHPublicKeyList(w, r)
	case r.Method == http.MethodPost && path == "/api/auth/ssh-keys":
		s.handleSSHPublicKeyCreate(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/auth/ssh-keys/"):
		s.handleSSHPublicKeyDelete(w, r)
	default:
		writeError(w, http.StatusNotFound, "SSH public key endpoint not found")
	}
}

func (s *Server) handleSSHPublicKeyList(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	items, err := s.sshPublicKeysForUser(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	result := make([]sshPublicKeyItem, 0, len(items))
	for _, item := range items {
		result = append(result, publicSSHPublicKeyItem(item))
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": result})
}

func (s *Server) handleSSHPublicKeyCreate(w http.ResponseWriter, r *http.Request) {
	var req sshPublicKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	key, comment, normalized, err := parseSSHPublicKey(req.PublicKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_, session, _ := s.authSession(r)
	fingerprint := ssh.FingerprintSHA256(key)
	existing, err := s.sshPublicKeysForUser(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, item := range existing {
		if firstMetadataString(item.Metadata, "fingerprint") == fingerprint {
			writeError(w, http.StatusConflict, "SSH public key is already registered")
			return
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = comment
	}
	if name == "" {
		name = key.Type() + " key"
	}
	item, err := s.cfg.Store.CreatePlatformItem(sshPublicKeyCollection, model.PlatformItemRequest{
		Name:        name,
		Type:        key.Type(),
		Status:      "enabled",
		OwnerID:     session.UserID,
		Username:    session.Username,
		Description: "SSH public key for native gateway authentication.",
		Metadata: map[string]any{
			"public_key":  normalized,
			"fingerprint": fingerprint,
			"comment":     comment,
			"created_ip":  s.clientIP(r),
			"user_agent":  strings.TrimSpace(r.UserAgent()),
		},
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.createSSHPublicKeyOperationLog(r, "auth.ssh_key.register", item, "registered SSH public key"); err != nil {
		if rollbackErr := s.cfg.Store.DeletePlatformItem(sshPublicKeyCollection, item.ID); rollbackErr != nil && !errors.Is(rollbackErr, os.ErrNotExist) {
			detail := "failed to remove SSH public key after operation log failure: " + rollbackErr.Error()
			_ = s.audit(r, "auth.ssh_key.restore_failed", item.ID, model.ProtocolSSH, detail)
			err = fmt.Errorf("%w; additionally %s", err, detail)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.ssh_key.register", item.ID, model.ProtocolSSH, "registered SSH public key")
	writeJSON(w, http.StatusCreated, publicSSHPublicKeyItem(item))
}

func (s *Server) handleSSHPublicKeyDelete(w http.ResponseWriter, r *http.Request) {
	_, session, _ := s.authSession(r)
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/auth/ssh-keys/"), "/")
	if id == "" {
		writeError(w, http.StatusNotFound, "SSH public key not found")
		return
	}
	item, ok, err := s.cfg.Store.GetPlatformItem(sshPublicKeyCollection, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok || item.OwnerID != session.UserID {
		writeError(w, http.StatusNotFound, "SSH public key not found")
		return
	}
	previous := item
	previous.Metadata = cloneMetadata(item.Metadata)
	if err := s.cfg.Store.DeletePlatformItem(sshPublicKeyCollection, id); err != nil {
		writeError(w, http.StatusNotFound, "SSH public key not found")
		return
	}
	if err := s.createSSHPublicKeyOperationLog(r, "auth.ssh_key.delete", item, "deleted SSH public key"); err != nil {
		if _, restoreErr := s.cfg.Store.SavePlatformItem(sshPublicKeyCollection, previous); restoreErr != nil {
			detail := "failed to restore deleted SSH public key: " + restoreErr.Error()
			_ = s.audit(r, "auth.ssh_key.restore_failed", id, model.ProtocolSSH, detail)
			err = fmt.Errorf("%w; additionally %s", err, detail)
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.audit(r, "auth.ssh_key.delete", id, model.ProtocolSSH, "deleted SSH public key")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) sshPublicKeysForUser(userID string) ([]model.PlatformItem, error) {
	items, err := s.cfg.Store.ListPlatformItems(sshPublicKeyCollection)
	if err != nil {
		return nil, err
	}
	result := make([]model.PlatformItem, 0, len(items))
	for _, item := range items {
		if item.OwnerID == userID {
			result = append(result, item)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if !result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].CreatedAt.Before(result[j].CreatedAt)
		}
		return result[i].ID < result[j].ID
	})
	return result, nil
}

func parseSSHPublicKey(value string) (ssh.PublicKey, string, string, error) {
	raw := []byte(strings.TrimSpace(value))
	if len(raw) == 0 {
		return nil, "", "", errors.New("SSH public key is required")
	}
	key, comment, _, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil || key == nil {
		return nil, "", "", errors.New("SSH public key is invalid")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, "", "", errors.New("only one SSH public key can be registered at a time")
	}
	if _, ok := key.(*ssh.Certificate); ok {
		return nil, "", "", errors.New("SSH certificates are not accepted as account public keys")
	}
	normalized := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	return key, strings.TrimSpace(comment), normalized, nil
}

func publicSSHPublicKeyItem(item model.PlatformItem) sshPublicKeyItem {
	return sshPublicKeyItem{
		ID:          item.ID,
		Name:        item.Name,
		Type:        item.Type,
		Status:      item.Status,
		PublicKey:   firstMetadataString(item.Metadata, "public_key"),
		Fingerprint: firstMetadataString(item.Metadata, "fingerprint"),
		Comment:     firstMetadataString(item.Metadata, "comment"),
		CreatedAt:   item.CreatedAt,
	}
}

func (s *Server) createSSHPublicKeyOperationLog(r *http.Request, name string, item model.PlatformItem, description string) error {
	return s.createOperationLog(r, model.PlatformItemRequest{
		Name:        name,
		Type:        "ssh_public_key",
		Status:      "success",
		Protocol:    model.ProtocolSSH,
		OwnerID:     item.OwnerID,
		TargetID:    item.ID,
		Description: description,
		Metadata: map[string]any{
			"fingerprint": firstMetadataString(item.Metadata, "fingerprint"),
			"key_type":    item.Type,
			"client_ip":   s.clientIP(r),
		},
	})
}
