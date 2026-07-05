package app

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"sort"
	"strconv"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

type smtpTestRequest struct {
	SettingID string `json:"setting_id"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Body      string `json:"body"`
}

type smtpDeliveryConfig struct {
	SettingID          string
	Host               string
	Port               int
	Username           string
	Password           string
	From               string
	To                 []string
	UseTLS             bool
	StartTLS           bool
	ServerName         string
	InsecureSkipVerify bool
}

func (s *Server) handleSMTPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req smtpTestRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	item, ok, err := s.smtpIntegrationSetting(req.SettingID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "SMTP integration setting not found")
		return
	}
	password, ok, err := s.cfg.Store.SystemSettingSMTPPassword(item.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "SMTP integration setting not found")
		return
	}
	cfg, err := smtpDeliveryConfigFromSetting(item, password, req.To)
	if err != nil {
		_ = s.audit(r, "system_settings.smtp_test.failed", item.ID, "", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		subject = "Open Web Server Manager SMTP test"
	}
	body := strings.TrimSpace(req.Body)
	if body == "" {
		body = "This is a test email from Open Web Server Manager."
	}
	started := time.Now()
	if err := sendSMTPTestMail(cfg, subject, body); err != nil {
		_ = s.audit(r, "system_settings.smtp_test.failed", item.ID, "", "SMTP test failed: "+err.Error())
		writeError(w, http.StatusBadGateway, "send SMTP test email: "+err.Error())
		return
	}
	_ = s.audit(r, "system_settings.smtp_test", item.ID, "", "sent SMTP test email")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"message":     "SMTP test email sent",
		"setting_id":  item.ID,
		"host":        cfg.Host,
		"port":        cfg.Port,
		"to":          cfg.To,
		"duration_ms": time.Since(started).Milliseconds(),
		"sent_at":     time.Now().UTC(),
	})
}

func (s *Server) smtpIntegrationSetting(id string) (model.PlatformItem, bool, error) {
	if strings.TrimSpace(id) != "" {
		return s.cfg.Store.GetPlatformItem("system_settings", strings.TrimSpace(id))
	}
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return model.PlatformItem{}, false, err
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].UpdatedAt.After(items[j].UpdatedAt)
	})
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Type), "integration") && platformItemEnabled(item) {
			return item, true, nil
		}
	}
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Type), "integration") {
			return item, true, nil
		}
	}
	return model.PlatformItem{}, false, nil
}

func smtpDeliveryConfigFromSetting(item model.PlatformItem, password, toOverride string) (smtpDeliveryConfig, error) {
	metadata := item.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	cfg := smtpDeliveryConfig{
		SettingID:          item.ID,
		Host:               firstNonEmpty(smtpMetadataString(metadata, "smtp_host", "host"), item.Host),
		Port:               smtpFirstNonZero(smtpMetadataInt(metadata, "smtp_port", "port"), item.Port, 587),
		Username:           firstNonEmpty(smtpMetadataString(metadata, "smtp_username", "username"), item.Username),
		Password:           password,
		From:               smtpMetadataString(metadata, "smtp_from", "from", "mail_from"),
		UseTLS:             smtpMetadataBoolAny(metadata, "smtp_use_tls", "smtp_ssl", "use_tls", "ssl", "tls"),
		StartTLS:           smtpMetadataBoolAny(metadata, "smtp_start_tls", "smtp_starttls", "start_tls", "starttls"),
		ServerName:         smtpMetadataString(metadata, "smtp_server_name", "server_name"),
		InsecureSkipVerify: smtpMetadataBoolAny(metadata, "smtp_insecure_skip_verify", "insecure_skip_verify"),
	}
	if cfg.From == "" {
		cfg.From = cfg.Username
	}
	recipients := splitRecipients(firstNonEmpty(strings.TrimSpace(toOverride), smtpMetadataString(metadata, "smtp_to", "to", "test_to")))
	if len(recipients) == 0 && cfg.From != "" {
		recipients = []string{cfg.From}
	}
	cfg.To = recipients
	if cfg.Host == "" {
		return smtpDeliveryConfig{}, errors.New("smtp_host is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return smtpDeliveryConfig{}, errors.New("smtp_port is invalid")
	}
	if cfg.From == "" {
		return smtpDeliveryConfig{}, errors.New("smtp_from is required")
	}
	if len(cfg.To) == 0 {
		return smtpDeliveryConfig{}, errors.New("smtp_to is required")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = cfg.Host
	}
	return cfg, nil
}

func sendSMTPTestMail(cfg smtpDeliveryConfig, subject, body string) error {
	address := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsConfig := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var client *smtp.Client
	if cfg.UseTLS {
		conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return err
		}
	} else {
		conn, err := dialer.Dial("tcp", address)
		if err != nil {
			return err
		}
		client, err = smtp.NewClient(conn, cfg.Host)
		if err != nil {
			_ = conn.Close()
			return err
		}
	}
	defer client.Close()
	if err := client.Hello("openwebservermanager"); err != nil {
		return err
	}
	if cfg.StartTLS && !cfg.UseTLS {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return errors.New("SMTP server does not advertise STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return err
		}
	}
	if cfg.Username != "" && cfg.Password != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return err
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return err
	}
	for _, recipient := range cfg.To {
		if err := client.Rcpt(recipient); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(writer, smtpMessage(cfg.From, cfg.To, subject, body)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func smtpMessage(from string, to []string, subject, body string) string {
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(to, ", "),
		"Subject: " + sanitizeSMTPHeader(subject),
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n"
}

func sanitizeSMTPHeader(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.TrimSpace(value)
}

func splitRecipients(value string) []string {
	result := []string{}
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r'
	}) {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func smtpMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case fmt.Stringer:
			if strings.TrimSpace(value.String()) != "" {
				return strings.TrimSpace(value.String())
			}
		}
	}
	return ""
}

func smtpMetadataInt(metadata map[string]any, keys ...string) int {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case int:
			return value
		case int64:
			return int(value)
		case float64:
			return int(value)
		case string:
			parsed, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil {
				return parsed
			}
		}
	}
	return 0
}

func smtpMetadataBoolAny(metadata map[string]any, keys ...string) bool {
	for _, key := range keys {
		switch value := metadata[key].(type) {
		case bool:
			if value {
				return true
			}
		case int:
			if value != 0 {
				return true
			}
		case float64:
			if value != 0 {
				return true
			}
		case string:
			switch strings.ToLower(strings.TrimSpace(value)) {
			case "true", "1", "yes", "enabled", "on":
				return true
			}
		}
	}
	return false
}

func smtpFirstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
