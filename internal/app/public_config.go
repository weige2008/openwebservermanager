package app

import (
	"encoding/json"
	"strings"

	"openwebservermanager/internal/model"
)

func (s *Server) publicConfig() PublicConfig {
	cfg := s.cfg.Public
	applyPublicConfigDefaults(&cfg)
	if s.cfg.Store == nil {
		return cfg
	}
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return cfg
	}
	branding, ok := findBrandingSetting(items)
	if !ok {
		return cfg
	}
	metadata := branding.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	if value := firstMetadataText(metadata, "site_name", "system_name", "product_name", "title"); value != "" {
		cfg.SiteName = value
	}
	if value := firstMetadataText(metadata, "github_url", "repository_url", "repo_url"); value != "" {
		cfg.GitHubURL = value
	}
	if value := firstMetadataText(metadata, "copyright", "copyright_text"); value != "" {
		cfg.Copyright = value
	}
	if value := firstMetadataText(metadata, "logo_url", "system_icon", "icon_url"); value != "" {
		cfg.LogoURL = value
	}
	if value := firstMetadataText(metadata, "asset_logo_url", "asset_logo"); value != "" {
		cfg.AssetLogoURL = value
	}
	if value := firstMetadataText(metadata, "icp_number", "icp", "beian", "record_number"); value != "" {
		cfg.ICPNumber = value
	}
	if value := firstMetadataText(metadata, "about_title"); value != "" {
		cfg.AboutTitle = value
	}
	if value := firstMetadataText(metadata, "about_description", "about_subtitle"); value != "" {
		cfg.AboutDescription = value
	}
	if value := firstMetadataText(metadata, "about_body", "about_content"); value != "" {
		cfg.AboutBody = value
	}
	if value := firstMetadataText(metadata, "footer_text", "footer"); value != "" {
		cfg.FooterText = value
	}
	if links := publicNavLinksFromMetadata(metadata["nav_links"]); len(links) > 0 {
		cfg.NavLinks = links
	} else if links := publicNavLinksFromMetadata(metadata["nav_links_json"]); len(links) > 0 {
		cfg.NavLinks = links
	}
	return cfg
}

func applyPublicConfigDefaults(cfg *PublicConfig) {
	if cfg.SiteName == "" {
		cfg.SiteName = "Open Web Server Manager"
	}
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	if cfg.GitHubURL == "" {
		cfg.GitHubURL = "https://github.com/weige2008/openwebservermanager"
	}
	if cfg.Copyright == "" {
		cfg.Copyright = "Copyright (c) 2026 weige2008. All rights reserved."
	}
	if len(cfg.NavLinks) == 0 {
		cfg.NavLinks = []PublicNavLink{
			{Title: "product", Href: "/#product"},
			{Title: "connections", Href: "/#connections"},
			{Title: "security", Href: "/#security"},
			{Title: "deploy", Href: "/#deploy"},
			{Title: "about", Href: "/about"},
		}
	}
}

func findBrandingSetting(items []model.PlatformItem) (model.PlatformItem, bool) {
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(item.Type), "branding") {
			return item, true
		}
	}
	return model.PlatformItem{}, false
}

func firstMetadataText(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := metadataText(metadata[key]); value != "" {
			return value
		}
	}
	return ""
}

func publicNavLinksFromMetadata(value any) []PublicNavLink {
	switch typed := value.(type) {
	case []PublicNavLink:
		return sanitizePublicNavLinks(typed)
	case []any:
		links := []PublicNavLink{}
		for _, item := range typed {
			if link, ok := publicNavLinkFromAny(item); ok {
				links = append(links, link)
			}
		}
		return sanitizePublicNavLinks(links)
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return nil
		}
		var links []PublicNavLink
		if err := json.Unmarshal([]byte(text), &links); err == nil {
			return sanitizePublicNavLinks(links)
		}
		var raw []map[string]any
		if err := json.Unmarshal([]byte(text), &raw); err != nil {
			return nil
		}
		for _, item := range raw {
			if link, ok := publicNavLinkFromAny(item); ok {
				links = append(links, link)
			}
		}
		return sanitizePublicNavLinks(links)
	default:
		return nil
	}
}

func publicNavLinkFromAny(value any) (PublicNavLink, bool) {
	item, ok := value.(map[string]any)
	if !ok {
		return PublicNavLink{}, false
	}
	title := firstMetadataText(item, "title", "label", "name")
	href := firstMetadataText(item, "href", "url", "path")
	if title == "" || href == "" {
		return PublicNavLink{}, false
	}
	external, _ := metadataBoolValue(item["external"])
	return PublicNavLink{Title: title, Href: href, External: external}, true
}

func sanitizePublicNavLinks(links []PublicNavLink) []PublicNavLink {
	result := []PublicNavLink{}
	for _, link := range links {
		title := strings.TrimSpace(link.Title)
		href := strings.TrimSpace(link.Href)
		if title == "" || href == "" {
			continue
		}
		result = append(result, PublicNavLink{Title: title, Href: href, External: link.External})
	}
	return result
}
