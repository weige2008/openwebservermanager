package app

import (
	"strings"

	"openwebservermanager/internal/model"
)

type desktopAccessPolicy struct {
	Width               int
	Height              int
	DPI                 int
	ColorDepth          int
	ClipboardEnabled    bool
	FileTransferEnabled bool
	RecordingEnabled    bool
	IgnoreCert          bool
	ReadOnly            bool
	ResizeMethod        string
	WatermarkEnabled    bool
	WatermarkText       string
	WatermarkColor      string
	WatermarkFontSize   int
}

func defaultDesktopAccessPolicy(protocol model.Protocol) desktopAccessPolicy {
	return desktopAccessPolicy{
		Width:               1440,
		Height:              900,
		DPI:                 96,
		ColorDepth:          24,
		ClipboardEnabled:    true,
		FileTransferEnabled: protocol == model.ProtocolRDP,
		RecordingEnabled:    false,
		IgnoreCert:          true,
		ReadOnly:            false,
		ResizeMethod:        "display-update",
		WatermarkEnabled:    false,
		WatermarkColor:      "rgba(255,255,255,0.18)",
		WatermarkFontSize:   28,
	}
}

func (s *Server) desktopAccessPolicy(protocol model.Protocol) desktopAccessPolicy {
	policy := defaultDesktopAccessPolicy(protocol)
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return policy
	}
	for _, item := range items {
		if !strings.EqualFold(strings.TrimSpace(item.Type), "access") || strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
			continue
		}
		applyDesktopAccessPolicyMetadata(&policy, protocol, item.Metadata)
		return policy
	}
	return policy
}

func applyDesktopAccessPolicyMetadata(policy *desktopAccessPolicy, protocol model.Protocol, metadata map[string]any) {
	if metadata == nil {
		return
	}
	prefix := strings.ToLower(string(protocol))
	if value, ok := metadataIntByKeys(metadata, prefix+"_width", "desktop_width", "width"); ok {
		policy.Width = clampInt(value, 640, 7680, policy.Width)
	}
	if value, ok := metadataIntByKeys(metadata, prefix+"_height", "desktop_height", "height"); ok {
		policy.Height = clampInt(value, 480, 4320, policy.Height)
	}
	if value, ok := metadataIntByKeys(metadata, prefix+"_dpi", "desktop_dpi", "dpi"); ok {
		policy.DPI = clampInt(value, 72, 240, policy.DPI)
	}
	if value, ok := metadataIntByKeys(metadata, prefix+"_color_depth", "desktop_color_depth", "color_depth"); ok {
		policy.ColorDepth = clampInt(value, 8, 32, policy.ColorDepth)
	}
	if value, ok := metadataBoolByKeys(metadata, prefix+"_clipboard_enabled", "desktop_clipboard_enabled", "clipboard_enabled"); ok {
		policy.ClipboardEnabled = value
	}
	if value, ok := metadataBoolByKeys(metadata, prefix+"_file_transfer_enabled", "desktop_file_transfer_enabled", "file_transfer_enabled"); ok {
		policy.FileTransferEnabled = value
	}
	if value, ok := metadataBoolByKeys(metadata, prefix+"_recording_enabled", "desktop_recording_enabled", "recording_enabled"); ok {
		policy.RecordingEnabled = value
	}
	if value, ok := metadataBoolByKeys(metadata, prefix+"_ignore_cert", "desktop_ignore_cert", "ignore_cert"); ok {
		policy.IgnoreCert = value
	}
	if value, ok := metadataBoolByKeys(metadata, prefix+"_read_only", "desktop_read_only", "read_only"); ok {
		policy.ReadOnly = value
	}
	if value := firstMetadataString(metadata, prefix+"_resize_method", "desktop_resize_method", "resize_method"); value != "" {
		policy.ResizeMethod = value
	}
	if value, ok := metadataBoolByKeys(metadata, prefix+"_watermark_enabled", "watermark_enabled"); ok {
		policy.WatermarkEnabled = value
	}
	if value := firstMetadataString(metadata, prefix+"_watermark_text", "watermark_text"); value != "" {
		policy.WatermarkText = value
	}
	if value := firstMetadataString(metadata, prefix+"_watermark_color", "watermark_color"); value != "" {
		policy.WatermarkColor = value
	}
	if value, ok := metadataIntByKeys(metadata, prefix+"_watermark_font_size", "watermark_font_size"); ok {
		policy.WatermarkFontSize = clampInt(value, 10, 96, policy.WatermarkFontSize)
	}
}

func metadataIntByKeys(metadata map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := metadataInt(metadata[key]); ok {
			return value, true
		}
	}
	return 0, false
}

func metadataBoolByKeys(metadata map[string]any, keys ...string) (bool, bool) {
	for _, key := range keys {
		if value, ok := metadataBoolValue(metadata[key]); ok {
			return value, true
		}
	}
	return false, false
}

func boolPtr(value bool) *bool {
	return &value
}

func boolPtrValue(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
