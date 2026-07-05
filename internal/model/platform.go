package model

import "time"

type PlatformItem struct {
	ID          string         `json:"id"`
	Module      string         `json:"module"`
	Name        string         `json:"name"`
	Type        string         `json:"type,omitempty"`
	Status      string         `json:"status,omitempty"`
	Protocol    Protocol       `json:"protocol,omitempty"`
	Host        string         `json:"host,omitempty"`
	Port        int            `json:"port,omitempty"`
	Username    string         `json:"username,omitempty"`
	Group       string         `json:"group,omitempty"`
	OwnerID     string         `json:"owner_id,omitempty"`
	ParentID    string         `json:"parent_id,omitempty"`
	TargetID    string         `json:"target_id,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Permissions map[string]bool `json:"permissions,omitempty"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

type PlatformItemRequest struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Status      string         `json:"status"`
	Protocol    Protocol       `json:"protocol"`
	Host        string         `json:"host"`
	Port        int            `json:"port"`
	Username    string         `json:"username"`
	Group       string         `json:"group"`
	OwnerID     string         `json:"owner_id"`
	ParentID    string         `json:"parent_id"`
	TargetID    string         `json:"target_id"`
	Password    string         `json:"password,omitempty"`
	Tags        []string       `json:"tags"`
	Permissions map[string]bool `json:"permissions"`
	Description string         `json:"description"`
	Metadata    map[string]any `json:"metadata"`
}
