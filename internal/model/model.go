package model

import "time"

type ServerOS string

const (
	ServerOSLinux   ServerOS = "linux"
	ServerOSWindows ServerOS = "windows"
)

type CredentialType string

const (
	CredentialSSHPassword CredentialType = "ssh_password"
	CredentialSSHKey      CredentialType = "ssh_key"
	CredentialRDPPassword CredentialType = "rdp_password"
)

type Protocol string

const (
	ProtocolSSH Protocol = "ssh"
	ProtocolRDP Protocol = "rdp"
)

type SessionStatus string

const (
	SessionPending SessionStatus = "pending"
	SessionActive  SessionStatus = "active"
	SessionClosed  SessionStatus = "closed"
	SessionFailed  SessionStatus = "failed"
)

type Server struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Host        string    `json:"host"`
	SSHPort     int       `json:"ssh_port"`
	RDPPort     int       `json:"rdp_port"`
	OS          ServerOS  `json:"os"`
	Group       string    `json:"group"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Credential struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Type              CredentialType `json:"type"`
	Username          string         `json:"username"`
	Domain            string         `json:"domain,omitempty"`
	EncryptedPassword string         `json:"encrypted_password,omitempty"`
	EncryptedKey      string         `json:"encrypted_key,omitempty"`
	EncryptedPhrase   string         `json:"encrypted_phrase,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

type CredentialPublic struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Type      CredentialType `json:"type"`
	Username  string         `json:"username"`
	Domain    string         `json:"domain,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (c Credential) Public() CredentialPublic {
	return CredentialPublic{
		ID:        c.ID,
		Name:      c.Name,
		Type:      c.Type,
		Username:  c.Username,
		Domain:    c.Domain,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

type ConnectionSession struct {
	ID             string        `json:"id"`
	Protocol       Protocol      `json:"protocol"`
	ServerID       string        `json:"server_id"`
	CredentialID   string        `json:"credential_id"`
	UserID         string        `json:"user_id"`
	Status         SessionStatus `json:"status"`
	ClientIP       string        `json:"client_ip"`
	Error          string        `json:"error,omitempty"`
	RecordingPath  string        `json:"recording_path,omitempty"`
	RecordingSize  int64         `json:"recording_size,omitempty"`
	Width          int           `json:"width,omitempty"`
	Height         int           `json:"height,omitempty"`
	StartedAt      time.Time     `json:"started_at"`
	EndedAt        *time.Time    `json:"ended_at,omitempty"`
	LastActivityAt time.Time     `json:"last_activity_at"`
}

type AuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	TargetID  string    `json:"target_id"`
	Protocol  Protocol  `json:"protocol,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	ClientIP  string    `json:"client_ip"`
	CreatedAt time.Time `json:"created_at"`
}

type SSHCreateRequest struct {
	ServerID     string `json:"server_id"`
	CredentialID string `json:"credential_id"`
	Cols         int    `json:"cols"`
	Rows         int    `json:"rows"`
	Term         string `json:"term"`
}

type RDPCreateRequest struct {
	ServerID         string `json:"server_id"`
	CredentialID     string `json:"credential_id"`
	Width            int    `json:"width"`
	Height           int    `json:"height"`
	DPI              int    `json:"dpi"`
	RecordingEnabled bool   `json:"recording_enabled"`
}
