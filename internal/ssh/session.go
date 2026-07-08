package sshsession

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
	"openwebservermanager/internal/ws"
)

var (
	ErrCommandBlocked        = errors.New("ssh command blocked")
	ErrCommandTimeout        = errors.New("ssh command timed out")
	ErrExecCommandLogPersist = errors.New("persist exec command log failed")
)

type Message struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols int    `json:"cols,omitempty"`
	Rows int    `json:"rows,omitempty"`
}

type ExecResult struct {
	SessionID         string `json:"session_id"`
	Command           string `json:"command"`
	Stdout            string `json:"stdout"`
	Stderr            string `json:"stderr"`
	ExitCode          int    `json:"exit_code"`
	Status            string `json:"status"`
	DurationMs        int64  `json:"duration_ms"`
	Action            string `json:"action"`
	Risk              string `json:"risk"`
	RuleID            string `json:"rule_id,omitempty"`
	RuleName          string `json:"rule_name,omitempty"`
	ApprovalID        string `json:"approval_id,omitempty"`
	ApprovedExecution bool   `json:"approved_execution,omitempty"`
	Blocked           bool   `json:"blocked"`
	Error             string `json:"error,omitempty"`
}

type Runner struct {
	Store          *store.Store
	Logger         *slog.Logger
	KnownHostsPath string
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

	client, err := dial(server, credential, secret, r.KnownHostsPath)
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
	interceptor := newCommandInterceptor(r.Store, session)

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
			filtered, events := interceptor.Process(raw)
			for _, event := range events {
				if event.Blocked {
					notice := base64.StdEncoding.EncodeToString([]byte(event.Notice))
					_ = conn.SendJSON(Message{Type: "stdout", Data: notice})
				}
			}
			if len(filtered) > 0 {
				if _, err := stdin.Write(filtered); err != nil {
					closeAll()
					return
				}
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

func (r Runner) RunCommand(session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret, command string, timeout time.Duration) (ExecResult, error) {
	return r.runCommand(session, server, credential, secret, command, timeout, "")
}

func (r Runner) RunApprovedCommand(session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret, command string, timeout time.Duration, approvalID string) (ExecResult, error) {
	return r.runCommand(session, server, credential, secret, command, timeout, strings.TrimSpace(approvalID))
}

func (r Runner) runCommand(session model.ConnectionSession, server model.Server, credential model.Credential, secret store.CredentialSecret, command string, timeout time.Duration, approvalID string) (ExecResult, error) {
	command = strings.TrimSpace(command)
	approvalID = strings.TrimSpace(approvalID)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	started := time.Now()
	interceptor := newCommandInterceptor(r.Store, session)
	decision := interceptor.evaluate(command)
	approvedExecution := approvalID != ""
	if approvedExecution && commandDecisionStatus(decision.Action, decision.Blocked) == "approval_required" {
		decision.Action = "approved"
		decision.Status = "submitted"
		decision.Blocked = false
	}
	result := ExecResult{
		SessionID:         session.ID,
		Command:           command,
		ExitCode:          -1,
		Status:            "running",
		Action:            decision.Action,
		Risk:              decision.Risk,
		RuleID:            decision.RuleID,
		RuleName:          decision.RuleName,
		ApprovalID:        approvalID,
		ApprovedExecution: approvedExecution,
		Blocked:           decision.Blocked,
	}
	if decision.Blocked {
		result.Status = decision.Status
		if commandDecisionStatus(decision.Action, decision.Blocked) == "approval_required" {
			approval, approvalErr := interceptor.createCommandApproval(command, decision, false, map[string]any{"source": "ssh_exec"})
			if approvalErr == nil && approval.ID != "" {
				result.ApprovalID = approval.ID
			} else if approvalErr != nil {
				result.Error = approvalErr.Error()
			}
		}
		if result.Error == "" {
			result.Error = commandBlockNotice(command, decision, result.ApprovalID)
		}
		result.DurationMs = time.Since(started).Milliseconds()
		metadata := map[string]any{
			"exit_code":       result.ExitCode,
			"duration_ms":     result.DurationMs,
			"stdout":          "",
			"stderr":          result.Error,
			"error":           result.Error,
			"approval_id":     result.ApprovalID,
			"approval_status": "pending",
		}
		if approvedExecution {
			metadata["approved_execution"] = true
			metadata["approval_status"] = "approved"
		}
		if logErr := interceptor.recordExec(command, decision, "ssh exec command "+decision.Status, metadata); logErr != nil {
			result.Error = logErr.Error()
			r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
			return result, logErr
		}
		r.finishExecSession(session.ID, model.SessionFailed, result.Error)
		return result, ErrCommandBlocked
	}

	_, _ = r.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
		item.Status = model.SessionActive
	})
	client, err := dial(server, credential, secret, r.KnownHostsPath)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		result.DurationMs = time.Since(started).Milliseconds()
		if logErr := interceptor.recordExec(command, decision, "ssh exec command failed", result.execMetadata()); logErr != nil {
			result.Error = logErr.Error()
			r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
			return result, logErr
		}
		r.finishExecSession(session.ID, model.SessionFailed, err.Error())
		return result, err
	}
	defer client.Close()
	sshSession, err := client.NewSession()
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		result.DurationMs = time.Since(started).Milliseconds()
		if logErr := interceptor.recordExec(command, decision, "ssh exec command failed", result.execMetadata()); logErr != nil {
			result.Error = logErr.Error()
			r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
			return result, logErr
		}
		r.finishExecSession(session.ID, model.SessionFailed, err.Error())
		return result, err
	}
	defer sshSession.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	sshSession.Stdout = &stdout
	sshSession.Stderr = &stderr
	errCh := make(chan error, 1)
	go func() {
		errCh <- sshSession.Run(command)
	}()
	select {
	case err = <-errCh:
	case <-time.After(timeout):
		_ = sshSession.Close()
		err = ErrCommandTimeout
	}
	result.Stdout = limitExecOutput(stdout.String())
	result.Stderr = limitExecOutput(stderr.String())
	result.DurationMs = time.Since(started).Milliseconds()
	if err == nil {
		result.ExitCode = 0
		result.Status = "success"
		if logErr := interceptor.recordExec(command, decision, "ssh exec command success", result.execMetadata()); logErr != nil {
			result.Error = logErr.Error()
			r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
			return result, logErr
		}
		r.finishExecSession(session.ID, model.SessionClosed, "")
		return result, nil
	}
	if errors.Is(err, ErrCommandTimeout) {
		result.Status = "timeout"
		result.Error = err.Error()
		if logErr := interceptor.recordExec(command, decision, "ssh exec command timeout", result.execMetadata()); logErr != nil {
			result.Error = logErr.Error()
			r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
			return result, logErr
		}
		r.finishExecSession(session.ID, model.SessionFailed, err.Error())
		return result, err
	}
	var exitErr *ssh.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitStatus()
		result.Status = "failed"
		result.Error = err.Error()
		if logErr := interceptor.recordExec(command, decision, "ssh exec command failed", result.execMetadata()); logErr != nil {
			result.Error = logErr.Error()
			r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
			return result, logErr
		}
		r.finishExecSession(session.ID, model.SessionClosed, err.Error())
		return result, nil
	}
	result.Status = "failed"
	result.Error = err.Error()
	if logErr := interceptor.recordExec(command, decision, "ssh exec command failed", result.execMetadata()); logErr != nil {
		result.Error = logErr.Error()
		r.finishExecSession(session.ID, model.SessionFailed, logErr.Error())
		return result, logErr
	}
	r.finishExecSession(session.ID, model.SessionFailed, err.Error())
	return result, err
}

func (r Runner) finishExecSession(sessionID string, status model.SessionStatus, reason string) {
	now := time.Now().UTC()
	_, _ = r.Store.UpdateSession(sessionID, func(item *model.ConnectionSession) {
		item.Status = status
		item.EndedAt = &now
		if reason != "" {
			item.Error = reason
		}
	})
}

func (r ExecResult) execMetadata() map[string]any {
	metadata := map[string]any{
		"exit_code":   r.ExitCode,
		"duration_ms": r.DurationMs,
		"stdout":      r.Stdout,
		"stderr":      r.Stderr,
		"error":       r.Error,
	}
	if r.ApprovalID != "" {
		metadata["approval_id"] = r.ApprovalID
		metadata["approved_execution"] = r.ApprovedExecution
	}
	return metadata
}

func limitExecOutput(value string) string {
	const limit = 128 * 1024
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n[openwebservermanager] output truncated"
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

func dial(server model.Server, credential model.Credential, secret store.CredentialSecret, knownHostsPath string) (*ssh.Client, error) {
	auth, err := authMethods(credential, secret)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(server.Host, strconv.Itoa(server.SSHPort))
	hostKeyCallback, err := hostKeyCallback(knownHostsPath)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            credential.Username,
		Auth:            auth,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}
	return ssh.Dial("tcp", addr, config)
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

var knownHostsMu sync.Mutex

func hostKeyCallback(path string) (ssh.HostKeyCallback, error) {
	if path == "" {
		return nil, fmt.Errorf("known hosts path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("prepare known_hosts directory: %w", err)
	}
	callback, err := knownhosts.New(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if callback != nil {
			err := callback(hostname, remote, key)
			if err == nil {
				return nil
			}
			var keyErr *knownhosts.KeyError
			if !errors.As(err, &keyErr) || len(keyErr.Want) > 0 {
				return err
			}
		}
		knownHostsMu.Lock()
		defer knownHostsMu.Unlock()
		line := knownhosts.Line([]string{hostname}, key)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("save known host key: %w", err)
		}
		defer file.Close()
		if _, err := file.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("write known host key: %w", err)
		}
		return nil
	}, nil
}
