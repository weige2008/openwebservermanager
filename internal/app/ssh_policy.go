package app

import (
	"strings"

	"openwebservermanager/internal/model"
)

type sshAccessPolicy struct {
	FileTransferEnabled bool
	WatermarkEnabled    bool
	WatermarkText       string
	WatermarkColor      string
	WatermarkFontSize   int
}

func defaultSSHAccessPolicy() sshAccessPolicy {
	return sshAccessPolicy{
		FileTransferEnabled: true,
		WatermarkColor:      "rgba(255,255,255,0.18)",
		WatermarkFontSize:   28,
	}
}

func (s *Server) sshAccessPolicy() sshAccessPolicy {
	policy := defaultSSHAccessPolicy()
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return policy
	}
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "access") || strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			continue
		}
		if value, ok := metadataBoolByKeys(item.Metadata, "ssh_file_transfer_enabled", "ssh_sftp_enabled"); ok {
			policy.FileTransferEnabled = value
		}
		if value, ok := metadataBoolByKeys(item.Metadata, "ssh_watermark_enabled", "watermark_enabled"); ok {
			policy.WatermarkEnabled = value
		}
		if value := firstMetadataString(item.Metadata, "ssh_watermark_text", "watermark_text"); value != "" {
			policy.WatermarkText = value
		}
		if value := firstMetadataString(item.Metadata, "ssh_watermark_color", "watermark_color"); value != "" {
			policy.WatermarkColor = value
		}
		if value, ok := metadataIntByKeys(item.Metadata, "ssh_watermark_font_size", "watermark_font_size"); ok {
			policy.WatermarkFontSize = clampInt(value, 10, 96, policy.WatermarkFontSize)
		}
		return policy
	}
	return policy
}

func applySSHAccessPolicy(session *model.ConnectionSession, policy sshAccessPolicy) {
	session.FileTransferEnabled = boolPtr(policy.FileTransferEnabled)
	session.WatermarkEnabled = boolPtr(policy.WatermarkEnabled)
	session.WatermarkText = policy.WatermarkText
	session.WatermarkColor = policy.WatermarkColor
	session.WatermarkFontSize = policy.WatermarkFontSize
}
