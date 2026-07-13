package app

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

const maxNotificationItems = 20
const maxNotificationReadKeys = 200
const notificationReadCollection = "notification_reads"

type notificationItem struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Category  string         `json:"category"`
	Title     string         `json:"title,omitempty"`
	Body      string         `json:"body,omitempty"`
	TitleKey  string         `json:"title_key,omitempty"`
	BodyKey   string         `json:"body_key,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Action    string         `json:"action,omitempty"`
	TargetID  string         `json:"target_id,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type notificationReadRequest struct {
	Keys []string `json:"keys"`
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, session, ok := s.authSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	items, err := s.buildNotifications(session)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	readKeys, err := s.notificationReadKeys(session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "read_keys": readKeys, "generated_at": time.Now().UTC()})
}

func (s *Server) handleNotificationRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	_, session, ok := s.authSession(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var req notificationReadRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	readKeys, err := s.saveNotificationReadKeys(session, req.Keys, s.clientIP(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"read_keys": readKeys, "updated_at": time.Now().UTC()})
}

func (s *Server) buildNotifications(session authSession) ([]notificationItem, error) {
	now := time.Now().UTC()
	s.refreshAgentGatewayStatuses()
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		return nil, err
	}
	_, _, sessions, _ := s.cfg.Store.Bootstrap()
	operator := notificationCanSeeSystem(s.roleDecision(session.Role))
	items := []notificationItem{}

	if operator {
		items = append(items, s.runtimeNotifications(now)...)
	}
	items = append(items, sessionNotifications(sessions, platform["online_sessions"], session.UserID, operator, now)...)
	items = append(items, loginNotifications(platform["login_logs"], session, operator)...)
	if operator {
		items = append(items, scheduledTaskNotifications(platform["operation_logs"])...)
		items = append(items, agentGatewayNotifications(platform["agent_gateways"], now)...)
		items = append(items, recentOperationNotifications(platform["operation_logs"])...)
	}

	sort.SliceStable(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > maxNotificationItems {
		items = items[:maxNotificationItems]
	}
	return items, nil
}

func (s *Server) notificationReadKeys(userID string) ([]string, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return []string{}, nil
	}
	item, ok, err := s.cfg.Store.GetPlatformItem(notificationReadCollection, userID)
	if err != nil || !ok {
		return []string{}, err
	}
	return notificationReadKeysFromMetadata(item.Metadata), nil
}

func (s *Server) saveNotificationReadKeys(session authSession, keys []string, clientIP string) ([]string, error) {
	existing, err := s.notificationReadKeys(session.UserID)
	if err != nil {
		return nil, err
	}
	readKeys := mergeNotificationReadKeys(existing, keys)
	now := time.Now().UTC()
	item := model.PlatformItem{
		ID:        session.UserID,
		Module:    notificationReadCollection,
		Name:      session.Username,
		Type:      "user",
		Status:    "active",
		OwnerID:   session.UserID,
		CreatedAt: now,
		UpdatedAt: now,
		Metadata: map[string]any{
			"read_keys":    readKeys,
			"read_count":   len(readKeys),
			"last_read_at": now.Format(time.RFC3339Nano),
			"client_ip":    strings.TrimSpace(clientIP),
		},
	}
	if existingItem, ok, err := s.cfg.Store.GetPlatformItem(notificationReadCollection, session.UserID); err != nil {
		return nil, err
	} else if ok && !existingItem.CreatedAt.IsZero() {
		item.CreatedAt = existingItem.CreatedAt
	}
	if _, err := s.cfg.Store.SavePlatformItem(notificationReadCollection, item); err != nil {
		return nil, err
	}
	return readKeys, nil
}

func notificationReadKeysFromMetadata(metadata map[string]any) []string {
	if metadata == nil {
		return []string{}
	}
	switch value := metadata["read_keys"].(type) {
	case []string:
		return mergeNotificationReadKeys(nil, value)
	case []any:
		keys := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				keys = append(keys, text)
			}
		}
		return mergeNotificationReadKeys(nil, keys)
	case string:
		parts := strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == '\n'
		})
		return mergeNotificationReadKeys(nil, parts)
	default:
		return []string{}
	}
}

func mergeNotificationReadKeys(existing, incoming []string) []string {
	result := make([]string, 0, len(existing)+len(incoming))
	seen := map[string]bool{}
	for _, key := range append(existing, incoming...) {
		normalized := normalizeNotificationReadKey(key)
		if normalized == "" {
			continue
		}
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, normalized)
	}
	if len(result) > maxNotificationReadKeys {
		result = result[len(result)-maxNotificationReadKeys:]
	}
	return result
}

func normalizeNotificationReadKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 200 {
		return ""
	}
	for _, r := range key {
		if r < 32 || r == 127 {
			return ""
		}
	}
	return key
}

func (s *Server) runtimeNotifications(now time.Time) []notificationItem {
	guacdStatus := s.currentGuacdStatus()
	guacdAddress := strings.TrimSpace(guacdStatus.Address)
	result := []notificationItem{}
	if guacdStatus.Status != "running" {
		result = append(result, notificationItem{
			ID:        "runtime:guacd:offline",
			Type:      "warning",
			Category:  "runtime",
			TitleKey:  "rdpGatewayOffline",
			BodyKey:   "rdpGatewayOfflineBody",
			Metadata:  map[string]any{"address": guacdAddress, "status": guacdStatus.Status, "last_error": guacdStatus.LastError},
			CreatedAt: now,
		})
	} else {
		result = append(result, notificationItem{
			ID:        "runtime:guacd:online",
			Type:      "success",
			Category:  "runtime",
			TitleKey:  "rdpGatewayOnline",
			Body:      guacdAddress,
			Metadata:  map[string]any{"address": guacdAddress},
			CreatedAt: now,
		})
	}
	if errText := strings.TrimSpace(s.sshGatewayLastError()); errText != "" {
		result = append(result, notificationItem{
			ID:        "runtime:ssh_gateway:error",
			Type:      "danger",
			Category:  "runtime",
			Title:     "SSH gateway error",
			Body:      errText,
			CreatedAt: now,
		})
	}
	return result
}

func sessionNotifications(sessions []model.ConnectionSession, online []model.PlatformItem, userID string, operator bool, now time.Time) []notificationItem {
	count := 0
	protocolCounts := map[string]int{}
	for _, session := range sessions {
		if session.Status != model.SessionActive && session.Status != model.SessionPending {
			continue
		}
		if !operator && session.UserID != userID {
			continue
		}
		count++
		protocolCounts[string(session.Protocol)]++
	}
	for _, item := range online {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status != string(model.SessionActive) && status != string(model.SessionPending) && status != "connected" {
			continue
		}
		if !operator && item.OwnerID != userID {
			continue
		}
		count++
		protocolCounts[string(item.Protocol)]++
	}
	if count == 0 {
		return nil
	}
	return []notificationItem{{
		ID:        "sessions:active:" + strconv.Itoa(count),
		Type:      "info",
		Category:  "session",
		TitleKey:  "notification.activeSessions",
		BodyKey:   "notification.activeSessionsBody",
		Metadata:  map[string]any{"count": count, "protocols": protocolCounts},
		CreatedAt: now.Add(-1 * time.Second),
	}}
}

func loginNotifications(logs []model.PlatformItem, session authSession, operator bool) []notificationItem {
	result := []notificationItem{}
	for _, item := range latestPlatformItems(logs, 8) {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status != "failed" && status != "denied" {
			continue
		}
		if !operator && !loginLogBelongsToSession(item, session) {
			continue
		}
		account := firstNonEmpty(firstMetadataString(item.Metadata, "account", "username"), item.Name)
		result = append(result, notificationItem{
			ID:        "login:" + item.ID,
			Type:      "danger",
			Category:  "security",
			TitleKey:  "notification.loginFailed",
			Body:      firstNonEmpty(item.Description, "login failed"),
			Metadata:  map[string]any{"account": account, "status": item.Status, "client_ip": firstMetadataString(item.Metadata, "client_ip")},
			Action:    item.Type,
			TargetID:  item.TargetID,
			CreatedAt: item.CreatedAt,
		})
	}
	return result
}

func scheduledTaskNotifications(logs []model.PlatformItem) []notificationItem {
	result := []notificationItem{}
	for _, item := range latestPlatformItems(logs, 10) {
		if item.Type != "scheduled_task" || strings.EqualFold(strings.TrimSpace(item.Status), "success") {
			continue
		}
		result = append(result, notificationItem{
			ID:        "task:" + item.ID,
			Type:      "warning",
			Category:  "task",
			TitleKey:  "notification.taskFailed",
			Body:      firstNonEmpty(item.Description, item.Name),
			Metadata:  map[string]any{"task": item.Name, "status": item.Status},
			TargetID:  item.TargetID,
			CreatedAt: item.CreatedAt,
		})
	}
	return result
}

func agentGatewayNotifications(gateways []model.PlatformItem, now time.Time) []notificationItem {
	result := []notificationItem{}
	for _, gateway := range gateways {
		if strings.EqualFold(strings.TrimSpace(gateway.Status), "offline") {
			createdAt := gateway.UpdatedAt
			if offlineAt, ok := metadataTime(gateway.Metadata["last_offline_at"]); ok {
				createdAt = offlineAt
			}
			if createdAt.IsZero() {
				createdAt = now.Add(-2 * time.Second)
			}
			result = append(result, notificationItem{
				ID:        "agent_gateway:" + gateway.ID + ":offline",
				Type:      "warning",
				Category:  "gateway",
				TitleKey:  "notification.agentGatewayOffline",
				Body:      gateway.Name,
				Metadata:  map[string]any{"gateway": gateway.Name, "last_seen_at": firstMetadataString(gateway.Metadata, "last_seen_at")},
				TargetID:  gateway.ID,
				CreatedAt: createdAt,
			})
		}
	}
	return result
}

func recentOperationNotifications(logs []model.PlatformItem) []notificationItem {
	result := []notificationItem{}
	for _, item := range latestPlatformItems(logs, 6) {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status == "success" || status == "" {
			continue
		}
		if item.Type == "scheduled_task" {
			continue
		}
		result = append(result, notificationItem{
			ID:        "operation:" + item.ID,
			Type:      notificationTypeForStatus(status),
			Category:  "operation",
			Title:     fmt.Sprintf("Operation %s", status),
			Body:      firstNonEmpty(item.Description, item.Name),
			Metadata:  map[string]any{"module": item.Type, "status": item.Status},
			TargetID:  item.TargetID,
			CreatedAt: item.CreatedAt,
		})
	}
	return result
}

func notificationCanSeeSystem(decision roleDecision) bool {
	return decision.Kind == roleSuperAdmin || decision.Kind == roleAdmin || decision.Kind == roleAuditor
}

func loginLogBelongsToSession(item model.PlatformItem, session authSession) bool {
	if item.OwnerID != "" && item.OwnerID == session.UserID {
		return true
	}
	account := strings.ToLower(strings.TrimSpace(firstNonEmpty(firstMetadataString(item.Metadata, "account", "username"), item.Name)))
	return account != "" && account == strings.ToLower(strings.TrimSpace(session.Username))
}

func latestPlatformItems(items []model.PlatformItem, limit int) []model.PlatformItem {
	next := append([]model.PlatformItem(nil), items...)
	sort.SliceStable(next, func(i, j int) bool {
		return next[i].CreatedAt.After(next[j].CreatedAt)
	})
	if limit > 0 && len(next) > limit {
		next = next[:limit]
	}
	return next
}

func notificationTypeForStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "failed", "error", "denied", "blocked":
		return "danger"
	case "warning", "pending":
		return "warning"
	default:
		return "info"
	}
}

func latestTime(left, right time.Time) time.Time {
	if left.After(right) {
		return left
	}
	return right
}
