package agentrelay

import "time"

type Claim struct {
	TunnelID string    `json:"tunnel_id"`
	Target   string    `json:"target"`
	Protocol string    `json:"protocol,omitempty"`
	Deadline time.Time `json:"deadline,omitempty"`
}
type RegisterRequest struct {
	RegistrationToken string   `json:"registration_token"`
	Name              string   `json:"name,omitempty"`
	Hostname          string   `json:"hostname,omitempty"`
	Version           string   `json:"version,omitempty"`
	OS                string   `json:"os,omitempty"`
	Arch              string   `json:"arch,omitempty"`
	Capabilities      []string `json:"capabilities,omitempty"`
}

type HeartbeatRequest struct {
	RegistrationToken string         `json:"registration_token"`
	Hostname          string         `json:"hostname,omitempty"`
	Version           string         `json:"version,omitempty"`
	LatencyMS         int            `json:"latency_ms,omitempty"`
	CPUPercent        float64        `json:"cpu_percent,omitempty"`
	MemoryUsedBytes   int64          `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes  int64          `json:"memory_total_bytes,omitempty"`
	DiskUsedBytes     int64          `json:"disk_used_bytes,omitempty"`
	DiskTotalBytes    int64          `json:"disk_total_bytes,omitempty"`
	ActiveSessions    int            `json:"active_sessions,omitempty"`
	NetworkRXBytes    int64          `json:"network_rx_bytes,omitempty"`
	NetworkTXBytes    int64          `json:"network_tx_bytes,omitempty"`
	Metrics           map[string]any `json:"metrics,omitempty"`
}

type FailureRequest struct {
	Error string `json:"error"`
}
