package app

import (
	"fmt"
	"net/http"
	"strings"

	"openwebservermanager/internal/model"
)

func validatePlatformItemRequest(collection string, req model.PlatformItemRequest) error {
	if collection != "storages" || req.Metadata == nil {
		return nil
	}
	if value, exists := req.Metadata["limit_bytes"]; exists && !metadataValueEmpty(value) {
		if _, ok := parseStorageByteSize(value); !ok {
			return fmt.Errorf("storage quota must be a positive byte value such as 1073741824 or 10GB")
		}
	}
	return nil
}

func (s *Server) handleAccessStorages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	items, err := s.cfg.Store.ListPlatformItems("storages")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	userID, isAdmin := s.accessUser(r)
	visible := make([]model.PlatformItem, 0, len(items))
	for _, item := range items {
		if !platformItemEnabled(item) || !storageAccessAllowed(item, userID, isAdmin) {
			continue
		}
		visible = append(visible, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": visible})
}

func (s *Server) handleAccessStorageOperation(w http.ResponseWriter, r *http.Request, rest string) {
	parts := splitPath(rest)
	if len(parts) < 2 {
		writeError(w, http.StatusNotFound, "storage file operation not found")
		return
	}
	storageID := parts[0]
	storage, ok, err := s.cfg.Store.GetPlatformItem("storages", storageID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok || !platformItemEnabled(storage) {
		writeError(w, http.StatusNotFound, "storage not found")
		return
	}
	userID, isAdmin := s.accessUser(r)
	if !storageAccessAllowed(storage, userID, isAdmin) {
		_ = s.audit(r, "access.storage.denied", storageID, "", "storage access denied")
		writeError(w, http.StatusForbidden, "storage access denied")
		return
	}
	if parts[1] == "mfa" {
		s.handleAccessMFAVerify(w, r)
		return
	}
	s.handleStorageFiles(w, r, storageID, parts[1])
}

func (s *Server) accessStorageItems(items []model.PlatformItem, userID string, isAdmin bool) []model.PlatformItem {
	visible := make([]model.PlatformItem, 0, len(items))
	for _, item := range items {
		if platformItemEnabled(item) && storageAccessAllowed(item, userID, isAdmin) {
			visible = append(visible, item)
		}
	}
	return visible
}

func storageAccessAllowed(item model.PlatformItem, userID string, isAdmin bool) bool {
	if isAdmin {
		return true
	}
	if strings.TrimSpace(userID) == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(item.OwnerID), strings.TrimSpace(userID)) {
		return true
	}
	if metadataBoolDefault(item.Metadata["shared"], false) || metadataBoolDefault(item.Metadata["shared_enabled"], false) {
		return true
	}
	for _, key := range []string{"shared_users", "user_ids", "authorized_user_ids"} {
		if gatewayGroupIDMatches(metadataStrings(item.Metadata[key]), userID, "") {
			return true
		}
	}
	return false
}
