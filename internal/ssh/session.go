package sshsession

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"servermanager/internal/model"
	"servermanager/internal/store"
	"servermanager/internal/ws"
)

type Message struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type Runner struct {
	Store  *store.Store
	Logger *slog.Logger
}

func (r Runner) Run(conn *ws.Conn, session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret, term string, cols, rows int) {
	defer conn.Close()

	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	if term == "" {
		term = "xterm-256color"
	}

	client, err := dial(server, credential, secret)
	if err != nil {
		r.fail(conn, session.ID, err)
		return
	}
	defer client.Close()

	sshSession, err := client.NewSession()
	if err != nil {
		r.fail(conn, session.ID, err)
		return
	}
	defer sshSession.Close()

	stdin, err := sshSession.StdinPipe()
	if err != nil {
		r.fail(conn, session.ID, err)
		return
	}
	stdout, err := sshSession.StdoutPipe()
	if err != nil {
		r.fail(conn, session.ID, err)
		return
	}
	stderr, err := sshSession.StderrPipe()
	if err != nil {
		r.fail(conn, session.ID, err)
		return
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sshSession.RequestPty(term, rows, cols, modes); err != nil {
		r.fail(conn, session.ID, err)
		return
	}
	if err := sshSession.Shell(); err != nil {
		r.fail(conn, session.ID, err)
		return
	}

	_, _ = r.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
		item.Status = model.SessionActive
	})
	_ = conn.SendJSON(Message{Type: "ready"})

	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = sshSession.Close()
			now := time.Now().UTC()
			_, _ = r.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
				item.Status = model.SessionClosed
				item.EndedAt = &now
			})
		})
	}

	go r.copyOutput(conn, session.ID, "stdout", stdout, closeAll)
	go r.copyOutput(conn, session.ID, "stderr", stderr, closeAll)

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			closeAll()
			return
		}
		switch msg.Type {
		case "stdin":
			raw, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				_ = conn.SendJSON(Message{Type: "error", Data: err.Error()})
				continue
			}
			if _, err := stdin.Write(raw); err != nil {
				closeAll()
				return
			}
		case "resize":
			if msg.Cols > 0 && msg.Rows > 0 {
				_ = sshSession.WindowChange(msg.Rows, msg.Cols)
			}
		case "ping":
			_ = conn.SendJSON(Message{Type: "pong"})
		case "close":
			closeAll()
			return
		}
	}
}

func (r Runner) copyOutput(conn *ws.Conn, sessionID, typ string, reader io.Reader, done func()) {
	buf := make([]byte, 8192)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			payload := base64.StdEncoding.EncodeToString(buf[:n])
			if sendErr := conn.SendJSON(Message{Type: typ, Data: payload}); sendErr != nil {
				done()
				return
			}
			_, _ = r.Store.UpdateSession(sessionID, func(item *model.ConnectionSession) {})
		}
		if err != nil {
			done()
			return
		}
	}
}

func (r Runner) fail(conn *ws.Conn, sessionID string, err error) {
	if r.Logger != nil {
		r.Logger.Warn("ssh session failed", "session", sessionID, "error", err)
	}
	now := time.Now().UTC()
	_, _ = r.Store.UpdateSession(sessionID, func(item *model.ConnectionSession) {
		item.Status = model.SessionFailed
		item.Error = err.Error()
		item.EndedAt = &now
	})
	_ = conn.SendJSON(Message{Type: "error", Data: err.Error()})
}

func dial(server model.Server, credential model.Credential, secret store.CredentialSecret) (*ssh.Client, error) {
	auth, err := authMethods(credential, secret)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            credential.Username,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", server.Host+":"+strconv.Itoa(server.SSHPort), config)
}

func authMethods(credential model.Credential, secret store.CredentialSecret) ([]ssh.AuthMethod, error) {
	switch credential.Type {
	case model.CredentialSSHPassword:
		return []ssh.AuthMethod{ssh.Password(secret.Password)}, nil
	case model.CredentialSSHKey:
		var signer ssh.Signer
		var err error
		if secret.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(secret.PrivateKey), []byte(secret.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(secret.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse ssh private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	default:
		return nil, fmt.Errorf("credential %s is not usable for ssh", credential.ID)
	}
}