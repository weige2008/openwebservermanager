package app

import (
	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

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
