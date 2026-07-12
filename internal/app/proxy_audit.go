package app

import (
	"errors"
	"time"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

type proxyConnectionAuditSpec struct {
	Name        string
	Type        string
	Description string
	Protocol    model.Protocol
}

func beginProxyConnectionAudit(st *store.Store, spec proxyConnectionAuditSpec, targetID, clientIP string) (model.PlatformItem, error) {
	if st == nil {
		return model.PlatformItem{}, errors.New("proxy connection audit store is unavailable")
	}
	return st.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        spec.Name,
		Type:        spec.Type,
		Status:      "pending",
		Protocol:    spec.Protocol,
		TargetID:    targetID,
		Description: spec.Description,
		Metadata: map[string]any{
			"client":                 clientIP,
			"target":                 targetID,
			"client_to_target_bytes": int64(0),
			"target_to_client_bytes": int64(0),
			"duration_ms":            int64(0),
			"error":                  "",
		},
	})
}

func finishProxyConnectionAudit(st *store.Store, item model.PlatformItem, status string, clientToTarget, targetToClient int64, duration time.Duration, errorText string) error {
	if st == nil || item.ID == "" {
		return errors.New("proxy connection audit record is unavailable")
	}
	metadata := item.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	metadata["client_to_target_bytes"] = clientToTarget
	metadata["target_to_client_bytes"] = targetToClient
	metadata["duration_ms"] = duration.Milliseconds()
	metadata["error"] = errorText
	_, err := st.UpdatePlatformItem("operation_logs", item.ID, model.PlatformItemRequest{
		Status:   status,
		Metadata: metadata,
	})
	return err
}

func auditProxyLogPersistFailure(st *store.Store, action string, protocol model.Protocol, targetID, clientIP, detail string) {
	if st == nil {
		return
	}
	_ = st.Audit(model.AuditLog{
		UserID:   "system",
		Action:   action,
		TargetID: targetID,
		Protocol: protocol,
		Detail:   detail,
		ClientIP: clientIP,
	})
}
