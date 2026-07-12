package app

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

const notificationDeliveryCollection = "notification_deliveries"
const maxNotificationDeliveryKeys = 1000

func (s *Server) dispatchEmailNotifications(now time.Time) error {
	setting, ok, err := s.smtpIntegrationSetting("")
	if err != nil || !ok {
		return err
	}
	if !smtpMetadataBoolAny(setting.Metadata, "smtp_notifications_enabled", "notifications_enabled") {
		return nil
	}
	state, exists, err := s.cfg.Store.GetPlatformItem(notificationDeliveryCollection, setting.ID)
	if err != nil {
		return err
	}
	if retryAt, ok := metadataTime(state.Metadata["next_retry_at"]); ok && retryAt.After(now) {
		return nil
	}

	password, ok, err := s.cfg.Store.SystemSettingSMTPPassword(setting.ID)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("SMTP integration setting not found")
	}
	cfg, err := smtpDeliveryConfigFromSetting(setting, password, "")
	if err != nil {
		return s.saveEmailNotificationFailure(setting, &state, now, err)
	}

	items, err := s.emailNotificationCandidates(now, setting.Metadata)
	if err != nil {
		return err
	}
	delivered := notificationDeliveryKeys(state.Metadata)
	keys := emailNotificationKeys(items)
	if !exists && !smtpMetadataBoolAny(setting.Metadata, "smtp_notifications_send_existing", "notifications_send_existing") {
		return s.saveEmailNotificationState(setting, state, keys, now, map[string]any{
			"initialized_at": now.Format(time.RFC3339Nano),
		})
	}
	pending := make([]notificationItem, 0, len(items))
	for _, item := range items {
		if !containsNotificationDeliveryKey(delivered, emailNotificationKey(item)) {
			pending = append(pending, item)
		}
	}
	if len(pending) == 0 {
		return nil
	}

	subject, body := s.emailNotificationMessage(pending)
	if err := sendSMTPTestMail(cfg, subject, body); err != nil {
		return s.saveEmailNotificationFailure(setting, &state, now, errors.New(sanitizeSMTPTestText(cfg, err.Error())))
	}

	delivered = mergeNotificationDeliveryKeys(delivered, emailNotificationKeys(pending))
	if err := s.saveEmailNotificationState(setting, state, delivered, now, map[string]any{
		"last_sent_at":    now.Format(time.RFC3339Nano),
		"last_sent_count": len(pending),
		"last_subject":    subject,
		"failure_count":   0,
		"last_error":      "",
		"next_retry_at":   "",
	}); err != nil {
		return err
	}
	_ = s.auditEmailNotification("notification.smtp.sent", setting.ID, fmt.Sprintf("sent %d notification(s)", len(pending)))
	return nil
}

func (s *Server) emailNotificationCandidates(now time.Time, settings map[string]any) ([]notificationItem, error) {
	s.refreshAgentGatewayStatuses()
	platform, err := s.cfg.Store.PlatformBootstrap()
	if err != nil {
		return nil, err
	}
	items := []notificationItem{}
	items = append(items, loginNotifications(platform["login_logs"], authSession{Role: string(roleAdmin)}, true)...)
	items = append(items, scheduledTaskNotifications(platform["operation_logs"])...)
	items = append(items, agentGatewayNotifications(platform["agent_gateways"], now)...)
	items = append(items, recentOperationNotifications(platform["operation_logs"])...)

	categoryValue, categoriesConfigured := firstMetadataValue(settings, "smtp_notification_categories", "notification_categories")
	allowedCategories := notificationEmailCategories(categoryValue)
	filtered := items[:0]
	for _, item := range items {
		if item.Type != "warning" && item.Type != "danger" {
			continue
		}
		if categoriesConfigured && !allowedCategories[strings.ToLower(strings.TrimSpace(item.Category))] {
			continue
		}
		filtered = append(filtered, item)
	}
	sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].CreatedAt.Before(filtered[j].CreatedAt) })
	return filtered, nil
}

func (s *Server) emailNotificationMessage(items []notificationItem) (string, string) {
	siteName := strings.TrimSpace(s.publicConfig().SiteName)
	if siteName == "" {
		siteName = "Open Web Server Manager"
	}
	subject := fmt.Sprintf("[%s] %d new alert(s)", siteName, len(items))
	lines := []string{fmt.Sprintf("%s detected %d new alert(s):", siteName, len(items)), ""}
	for _, item := range items {
		lines = append(lines, fmt.Sprintf("- %s [%s/%s] %s: %s", item.CreatedAt.UTC().Format(time.RFC3339), item.Category, item.Type, notificationEmailTitle(item), firstNonEmpty(item.Body, "No additional detail")))
	}
	lines = append(lines, "", "Open the administration console to review the related audit records.")
	return subject, strings.Join(lines, "\n")
}

func notificationEmailTitle(item notificationItem) string {
	if strings.TrimSpace(item.Title) != "" {
		return strings.TrimSpace(item.Title)
	}
	switch item.TitleKey {
	case "notification.loginFailed":
		return "Login failed"
	case "notification.taskFailed":
		return "Scheduled task failed"
	case "notification.agentGatewayOffline":
		return "Agent gateway offline"
	default:
		return firstNonEmpty(item.TitleKey, "System alert")
	}
}

func emailNotificationKey(item notificationItem) string {
	if item.Category == "gateway" {
		return item.ID + ":" + item.CreatedAt.UTC().Format(time.RFC3339Nano)
	}
	return item.ID
}

func emailNotificationKeys(items []notificationItem) []string {
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, emailNotificationKey(item))
	}
	return keys
}

func notificationDeliveryKeys(metadata map[string]any) []string {
	if metadata == nil {
		return nil
	}
	return mergeNotificationDeliveryKeys(nil, metadataStrings(metadata["delivered_keys"]))
}

func mergeNotificationDeliveryKeys(existing, incoming []string) []string {
	result := make([]string, 0, len(existing)+len(incoming))
	seen := map[string]bool{}
	for _, key := range append(existing, incoming...) {
		key = normalizeNotificationReadKey(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, key)
	}
	if len(result) > maxNotificationDeliveryKeys {
		result = result[len(result)-maxNotificationDeliveryKeys:]
	}
	return result
}

func containsNotificationDeliveryKey(keys []string, target string) bool {
	for _, key := range keys {
		if key == target {
			return true
		}
	}
	return false
}

func (s *Server) saveEmailNotificationFailure(setting model.PlatformItem, existing *model.PlatformItem, now time.Time, sendErr error) error {
	state := model.PlatformItem{}
	if existing != nil {
		state = *existing
	}
	failures := maxInt(metadataIntDefault(state.Metadata["failure_count"], 0), 0) + 1
	retryDelay := time.Minute * time.Duration(1<<minInt(failures-1, 5))
	if retryDelay > 30*time.Minute {
		retryDelay = 30 * time.Minute
	}
	errText := strings.TrimSpace(sendErr.Error())
	if err := s.saveEmailNotificationState(setting, state, notificationDeliveryKeys(state.Metadata), now, map[string]any{
		"failure_count":  failures,
		"last_error":     errText,
		"last_failed_at": now.Format(time.RFC3339Nano),
		"next_retry_at":  now.Add(retryDelay).Format(time.RFC3339Nano),
	}); err != nil {
		return fmt.Errorf("%w; persist notification delivery failure: %v", sendErr, err)
	}
	_ = s.auditEmailNotification("notification.smtp.failed", setting.ID, errText)
	return sendErr
}

func (s *Server) auditEmailNotification(action, targetID, detail string) error {
	return s.cfg.Store.Audit(model.AuditLog{
		UserID:   "system",
		Action:   action,
		TargetID: targetID,
		Detail:   detail,
	})
}

func (s *Server) saveEmailNotificationState(setting, existing model.PlatformItem, keys []string, now time.Time, updates map[string]any) error {
	metadata := cloneMetadata(existing.Metadata)
	metadata["delivered_keys"] = mergeNotificationDeliveryKeys(nil, keys)
	metadata["delivered_count"] = len(notificationDeliveryKeys(metadata))
	for key, value := range updates {
		metadata[key] = value
	}
	createdAt := existing.CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}
	_, err := s.cfg.Store.SavePlatformItem(notificationDeliveryCollection, model.PlatformItem{
		ID:        setting.ID,
		Module:    notificationDeliveryCollection,
		Name:      setting.Name,
		Type:      "smtp",
		Status:    "active",
		OwnerID:   "system",
		CreatedAt: createdAt,
		UpdatedAt: now,
		Metadata:  metadata,
	})
	return err
}

func notificationEmailCategories(value any) map[string]bool {
	result := map[string]bool{}
	for _, category := range metadataStrings(value) {
		category = strings.ToLower(strings.TrimSpace(category))
		if category != "" {
			result[category] = true
		}
	}
	return result
}

func firstMetadataValue(metadata map[string]any, keys ...string) (any, bool) {
	for _, key := range keys {
		if value, ok := metadata[key]; ok {
			return value, true
		}
	}
	return nil, false
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
