package sshsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"
	"openwebservermanager/internal/store"
)

func TestNativeSSHGatewayConnectsAuthorizedAsset(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHServer(t, "remote", "target-secret")
	defer closeTarget()

	st := newGatewayTestStore(t)
	userRec, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "gateway-user",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "user"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port := mustAtoi(t, portText)
	assetRec, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "authorized-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "forbidden-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	}); err != nil {
		t.Fatalf("create forbidden asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("credentials", model.PlatformItemRequest{
		Name:     "remote-password",
		Type:     string(model.CredentialSSHPassword),
		Status:   "encrypted",
		Username: "remote",
		Password: "target-secret",
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:     "gateway-user authorized ssh",
		Status:   "enabled",
		OwnerID:  userRec.ID,
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create authorization: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "gateway-user",
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new gateway session: %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("start gateway shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "1\r"); err != nil {
		t.Fatalf("select asset: %v", err)
	}
	output := readUntilContains(t, stdout, "target-shell", 5*time.Second)
	if !strings.Contains(output, "authorized-ssh") {
		t.Fatalf("gateway menu did not show authorized asset: %q", output)
	}
	if strings.Contains(output, "forbidden-ssh") {
		t.Fatalf("gateway menu leaked unauthorized asset: %q", output)
	}
	if !strings.Contains(output, "target-shell") {
		t.Fatalf("gateway did not proxy target shell: %q", output)
	}
	logs, err := st.ListPlatformItems("operation_logs")
	if err != nil {
		t.Fatalf("list operation logs: %v", err)
	}
	joined := ""
	for _, log := range logs {
		joined += log.Name + "\n"
	}
	if !strings.Contains(joined, "ssh_gateway.login") || !strings.Contains(joined, "ssh_gateway.connect") {
		t.Fatalf("gateway login/connect audit missing: %s", joined)
	}
}

func TestNativeSSHGatewayDirectAssetLogin(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHServer(t, "remote", "target-secret")
	defer closeTarget()

	st := newGatewayTestStore(t)
	assetRec := createGatewayUserAssetAndCredential(t, st, targetAddr)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "gateway-user#" + assetRec.Name,
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new gateway session: %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("start gateway shell: %v", err)
	}
	output := readUntilContains(t, stdout, "target-shell", 5*time.Second)
	if strings.Contains(output, "Select asset") {
		t.Fatalf("direct asset login unexpectedly showed menu: %q", output)
	}
	if !strings.Contains(output, "Connecting to "+assetRec.Name) || !strings.Contains(output, "target-shell") {
		t.Fatalf("direct asset login did not reach target: %q", output)
	}
}

func TestNativeSSHGatewayRejectsExpiredAuthorization(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHServer(t, "remote", "target-secret")
	defer closeTarget()

	st := newGatewayTestStore(t)
	userRec, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "gateway-expiry-user",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "user"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port := mustAtoi(t, portText)
	activeAsset, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "future-grant-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create active asset: %v", err)
	}
	expiredAsset, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "expired-grant-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create expired asset: %v", err)
	}
	for _, asset := range []model.PlatformItem{activeAsset, expiredAsset} {
		if _, err := st.CreatePlatformItem("credentials", model.PlatformItemRequest{
			Name:     asset.Name + " password",
			Type:     string(model.CredentialSSHPassword),
			Status:   "encrypted",
			Username: "remote",
			Password: "target-secret",
			TargetID: asset.ID,
		}); err != nil {
			t.Fatalf("create credential for %s: %v", asset.Name, err)
		}
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:     "future grant",
		Status:   "enabled",
		OwnerID:  userRec.ID,
		TargetID: activeAsset.ID,
		Metadata: map[string]any{"expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)},
	}); err != nil {
		t.Fatalf("create future grant: %v", err)
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:     "expired grant",
		Status:   "enabled",
		OwnerID:  userRec.ID,
		TargetID: expiredAsset.ID,
		Metadata: map[string]any{"expires_at": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)},
	}); err != nil {
		t.Fatalf("create expired grant: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "gateway-expiry-user",
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new gateway session: %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("start gateway shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "1\r"); err != nil {
		t.Fatalf("select asset: %v", err)
	}
	output := readUntilContains(t, stdout, "target-shell", 5*time.Second)
	if !strings.Contains(output, activeAsset.Name) {
		t.Fatalf("gateway menu did not show active future grant: %q", output)
	}
	if strings.Contains(output, expiredAsset.Name) {
		t.Fatalf("gateway menu exposed expired authorization: %q", output)
	}

	directClient, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "gateway-expiry-user#" + expiredAsset.Name,
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway direct expired asset: %v", err)
	}
	defer directClient.Close()
	directSession, err := directClient.NewSession()
	if err != nil {
		t.Fatalf("new direct gateway session: %v", err)
	}
	defer directSession.Close()
	directStdout, err := directSession.StdoutPipe()
	if err != nil {
		t.Fatalf("direct stdout pipe: %v", err)
	}
	if err := directSession.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request direct pty: %v", err)
	}
	if err := directSession.Shell(); err != nil {
		t.Fatalf("start direct gateway shell: %v", err)
	}
	directOutput := readUntilContains(t, directStdout, "is not authorized or does not exist", 5*time.Second)
	if strings.Contains(directOutput, "target-shell") {
		t.Fatalf("direct login used expired authorization: %q", directOutput)
	}
}

func TestNativeSSHGatewayDepartmentAndAssetGroupAuthorization(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHServer(t, "remote", "target-secret")
	defer closeTarget()

	st := newGatewayTestStore(t)
	parentDept, err := st.CreatePlatformItem("departments", model.PlatformItemRequest{
		Name:   "Engineering",
		Type:   "department",
		Status: "enabled",
	})
	if err != nil {
		t.Fatalf("create parent department: %v", err)
	}
	childDept, err := st.CreatePlatformItem("departments", model.PlatformItemRequest{
		Name:     "Platform",
		Type:     "department",
		Status:   "enabled",
		ParentID: parentDept.ID,
	})
	if err != nil {
		t.Fatalf("create child department: %v", err)
	}
	userRec, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "gateway-department-user",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		ParentID: childDept.ID,
		Metadata: map[string]any{"role": "user"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	parentGroup, err := st.CreatePlatformItem("asset_groups", model.PlatformItemRequest{
		Name:   "Linux Fleet",
		Type:   "ssh",
		Status: "enabled",
	})
	if err != nil {
		t.Fatalf("create parent group: %v", err)
	}
	childGroup, err := st.CreatePlatformItem("asset_groups", model.PlatformItemRequest{
		Name:     "Production Linux",
		Type:     "ssh",
		Status:   "enabled",
		ParentID: parentGroup.ID,
	})
	if err != nil {
		t.Fatalf("create child group: %v", err)
	}
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port := mustAtoi(t, portText)
	assetRec, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "department-group-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
		Group:    childGroup.ID,
	})
	if err != nil {
		t.Fatalf("create grouped asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("credentials", model.PlatformItemRequest{
		Name:     "department target password",
		Type:     string(model.CredentialSSHPassword),
		Status:   "encrypted",
		Username: "remote",
		Password: "target-secret",
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:     "engineering linux fleet",
		Type:     "department_group",
		Status:   "enabled",
		OwnerID:  parentDept.ID,
		TargetID: parentGroup.ID,
	}); err != nil {
		t.Fatalf("create department group authorization: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            userRec.Name,
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new gateway session: %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("start gateway shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "1\r"); err != nil {
		t.Fatalf("select asset: %v", err)
	}
	output := readUntilContains(t, stdout, "target-shell", 5*time.Second)
	if !strings.Contains(output, assetRec.Name) || !strings.Contains(output, "target-shell") {
		t.Fatalf("department and asset group authorization did not reach target: %q", output)
	}
}

func TestNativeSSHGatewayAuthorizationMetadataAliases(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHServer(t, "remote", "target-secret")
	defer closeTarget()

	st := newGatewayTestStore(t)
	userRec, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "gateway-alias-user",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "user"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	groupRec, err := st.CreatePlatformItem("asset_groups", model.PlatformItemRequest{
		Name:   "Alias Linux",
		Type:   "ssh",
		Status: "enabled",
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port := mustAtoi(t, portText)
	assetRec, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "alias-metadata-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
		Metadata: map[string]any{"assetGroupId": groupRec.ID},
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("credentials", model.PlatformItemRequest{
		Name:     "alias metadata password",
		Type:     string(model.CredentialSSHPassword),
		Status:   "encrypted",
		Username: "remote",
		Password: "target-secret",
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:   "alias metadata grant",
		Type:   "metadata_aliases",
		Status: "enabled",
		Metadata: map[string]any{
			"subjectId":    userRec.ID,
			"assetGroupId": groupRec.ID,
		},
	}); err != nil {
		t.Fatalf("create metadata alias authorization: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            userRec.Name,
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("new gateway session: %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	if err := session.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request pty: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("start gateway shell: %v", err)
	}
	if _, err := io.WriteString(stdin, "1\r"); err != nil {
		t.Fatalf("select asset: %v", err)
	}
	output := readUntilContains(t, stdout, "target-shell", 5*time.Second)
	if !strings.Contains(output, assetRec.Name) || !strings.Contains(output, "target-shell") {
		t.Fatalf("metadata alias authorization did not reach target: %q", output)
	}
}

func TestNativeSSHGatewayChineseAdminDirectAssetLoginWithoutGrant(t *testing.T) {
	targetAddr, closeTarget := startFakeSSHServer(t, "remote", "target-secret")
	defer closeTarget()

	st := newGatewayTestStore(t)
	if _, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "chinese-admin",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "超级管理员"},
	}); err != nil {
		t.Fatalf("create chinese admin: %v", err)
	}
	if _, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "chinese-auditor",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "审计员"},
	}); err != nil {
		t.Fatalf("create chinese auditor: %v", err)
	}
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port := mustAtoi(t, portText)
	assetRec, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "ungranted-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("credentials", model.PlatformItemRequest{
		Name:     "remote-password",
		Type:     string(model.CredentialSSHPassword),
		Status:   "encrypted",
		Username: "remote",
		Password: "target-secret",
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	adminClient, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "chinese-admin#" + assetRec.Name,
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway as chinese admin: %v", err)
	}
	defer adminClient.Close()
	adminSession, err := adminClient.NewSession()
	if err != nil {
		t.Fatalf("new admin gateway session: %v", err)
	}
	defer adminSession.Close()
	adminStdout, err := adminSession.StdoutPipe()
	if err != nil {
		t.Fatalf("admin stdout pipe: %v", err)
	}
	if err := adminSession.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request admin pty: %v", err)
	}
	if err := adminSession.Shell(); err != nil {
		t.Fatalf("start admin gateway shell: %v", err)
	}
	adminOutput := readUntilContains(t, adminStdout, "target-shell", 5*time.Second)
	if !strings.Contains(adminOutput, "Connecting to "+assetRec.Name) || !strings.Contains(adminOutput, "target-shell") {
		t.Fatalf("chinese admin did not reach ungranted target: %q", adminOutput)
	}

	auditorClient, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "chinese-auditor#" + assetRec.Name,
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway as chinese auditor: %v", err)
	}
	defer auditorClient.Close()
	auditorSession, err := auditorClient.NewSession()
	if err != nil {
		t.Fatalf("new auditor gateway session: %v", err)
	}
	defer auditorSession.Close()
	auditorStdout, err := auditorSession.StdoutPipe()
	if err != nil {
		t.Fatalf("auditor stdout pipe: %v", err)
	}
	if err := auditorSession.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		t.Fatalf("request auditor pty: %v", err)
	}
	if err := auditorSession.Shell(); err != nil {
		t.Fatalf("start auditor gateway shell: %v", err)
	}
	auditorOutput := readUntilContains(t, auditorStdout, "No authorized SSH assets.", 5*time.Second)
	if strings.Contains(auditorOutput, "target-shell") || strings.Contains(auditorOutput, assetRec.Name) {
		t.Fatalf("chinese auditor was treated as an admin: %q", auditorOutput)
	}
}

func TestNativeSSHGatewayDirectTCPIPForwarding(t *testing.T) {
	echoAddr, closeEcho := startTCPEchoServer(t)
	defer closeEcho()

	st := newGatewayTestStore(t)
	userRec, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "gateway-user",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "user"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	host, portText, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatalf("split echo addr: %v", err)
	}
	port := mustAtoi(t, portText)
	assetRec, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "echo-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:     "gateway-user authorized echo",
		Status:   "enabled",
		OwnerID:  userRec.ID,
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create authorization: %v", err)
	}
	if _, err := st.CreatePlatformItem("ssh_gateways", model.PlatformItemRequest{
		Name:   "gateway-forward-policy",
		Status: "enabled",
		Metadata: map[string]any{
			"forward_allowlist": []string{echoAddr},
		},
	}); err != nil {
		t.Fatalf("create gateway policy: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gatewayDataDir := mustTempDir(t)
	defer removeTempDir(gatewayDataDir)
	gateway, err := StartGateway(ctx, GatewayConfig{
		Enabled:        true,
		Address:        "127.0.0.1:0",
		DataDir:        gatewayDataDir,
		KnownHostsPath: filepath.Join(gatewayDataDir, "known_hosts"),
		Store:          st,
	})
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User:            "gateway-user",
		Auth:            []ssh.AuthMethod{ssh.Password("password123")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer client.Close()

	assetForward, err := client.Dial("tcp", net.JoinHostPort(assetRec.Name, strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("dial authorized asset forward: %v", err)
	}
	assertEchoRoundTrip(t, assetForward, "asset-forward")
	_ = assetForward.Close()

	allowlistForward, err := client.Dial("tcp", echoAddr)
	if err != nil {
		t.Fatalf("dial allowlisted forward: %v", err)
	}
	assertEchoRoundTrip(t, allowlistForward, "allowlist-forward")
	_ = allowlistForward.Close()

	if denied, err := client.Dial("tcp", net.JoinHostPort(host, "1")); err == nil {
		_ = denied.Close()
		t.Fatal("expected non-allowlisted direct-tcpip target to be denied")
	}

	logs, err := st.ListPlatformItems("operation_logs")
	if err != nil {
		t.Fatalf("list operation logs: %v", err)
	}
	joined := ""
	for _, log := range logs {
		joined += log.Name + " " + log.TargetID + "\n"
	}
	if !strings.Contains(joined, "ssh_gateway.forward.started") || !strings.Contains(joined, "ssh_gateway.forward.denied") {
		t.Fatalf("forward audit missing: %s", joined)
	}
}

func TestGatewayConfigFromEnabledStoreItem(t *testing.T) {
	st := newGatewayTestStore(t)
	if _, err := st.CreatePlatformItem("ssh_gateways", model.PlatformItemRequest{
		Name:   "builtin",
		Status: "enabled",
		Host:   "127.0.0.1",
		Port:   22022,
		Metadata: map[string]any{
			"disable_password_auth": true,
		},
	}); err != nil {
		t.Fatalf("create gateway item: %v", err)
	}
	cfg, err := GatewayConfigFromStore(st, t.TempDir(), "")
	if err != nil {
		t.Fatalf("gateway config: %v", err)
	}
	if !cfg.Enabled || cfg.Address != "127.0.0.1:22022" || !cfg.DisablePasswordAuth {
		t.Fatalf("gateway config = %#v", cfg)
	}
}

func TestGatewayConfigUsesProxyServicePrivateKeyAsHostKey(t *testing.T) {
	st := newGatewayTestStore(t)
	hostKeyPEM, expectedSigner := testSSHHostKeyPEM(t)

	settings, err := st.ListPlatformItems("system_settings")
	if err != nil {
		t.Fatalf("list system settings: %v", err)
	}
	proxySettingID := ""
	for _, item := range settings {
		if strings.EqualFold(item.Type, "proxy") {
			proxySettingID = item.ID
			break
		}
	}
	if proxySettingID == "" {
		t.Fatal("proxy system setting was not seeded")
	}
	if _, err := st.UpdatePlatformItem("system_settings", proxySettingID, model.PlatformItemRequest{
		Name:   "Proxy service settings",
		Type:   "proxy",
		Status: "enabled",
		Metadata: map[string]any{
			"proxy_private_key": hostKeyPEM,
		},
	}); err != nil {
		t.Fatalf("save proxy private key: %v", err)
	}
	if _, err := st.CreatePlatformItem("ssh_gateways", model.PlatformItemRequest{
		Name:   "builtin",
		Status: "enabled",
		Metadata: map[string]any{
			"listen_address": "127.0.0.1:0",
		},
	}); err != nil {
		t.Fatalf("create gateway item: %v", err)
	}

	cfg, err := GatewayConfigFromStore(st, t.TempDir(), "")
	if err != nil {
		t.Fatalf("gateway config: %v", err)
	}
	if strings.TrimSpace(cfg.HostKeyPEM) == "" {
		t.Fatal("gateway config did not load proxy private key")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway, err := StartGateway(ctx, cfg)
	if err != nil {
		t.Fatalf("start gateway: %v", err)
	}
	defer gateway.Close()

	observed := make(chan string, 1)
	client, err := ssh.Dial("tcp", gateway.Address(), &ssh.ClientConfig{
		User: "nobody",
		Auth: []ssh.AuthMethod{ssh.Password("wrong-password")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			observed <- ssh.FingerprintSHA256(key)
			return nil
		},
		Timeout: 3 * time.Second,
	})
	if err == nil {
		_ = client.Close()
		t.Fatal("expected authentication failure")
	}

	select {
	case fingerprint := <-observed:
		expected := ssh.FingerprintSHA256(expectedSigner.PublicKey())
		if fingerprint != expected {
			t.Fatalf("gateway host key fingerprint = %s, want %s", fingerprint, expected)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ssh client did not observe gateway host key")
	}
}

func TestGatewayManagerReloadStartsAndStopsGateway(t *testing.T) {
	st := newGatewayTestStore(t)
	gatewayItem, err := st.CreatePlatformItem("ssh_gateways", model.PlatformItemRequest{
		Name:   "builtin",
		Status: "enabled",
		Metadata: map[string]any{
			"listen_address": "127.0.0.1:0",
		},
	})
	if err != nil {
		t.Fatalf("create gateway item: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewGatewayManager(ctx, st, t.TempDir(), "", nil)
	defer manager.Close()
	if err := manager.Reload(); err != nil {
		t.Fatalf("reload start gateway: %v", err)
	}
	address := manager.Address()
	if address == "" {
		t.Fatal("gateway manager did not expose live address")
	}
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatalf("dial live gateway: %v", err)
	}
	_ = conn.Close()

	if _, err := st.UpdatePlatformItem("ssh_gateways", gatewayItem.ID, model.PlatformItemRequest{
		Name:   "builtin",
		Status: "disabled",
		Metadata: map[string]any{
			"listen_address": "127.0.0.1:0",
		},
	}); err != nil {
		t.Fatalf("disable gateway item: %v", err)
	}
	if err := manager.Reload(); err != nil {
		t.Fatalf("reload stopped gateway: %v", err)
	}
	if manager.Address() != "" {
		t.Fatalf("gateway manager address after disable = %q, want empty", manager.Address())
	}
	if conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("old gateway address %s still accepts connections after disable", address)
	}
}

func createGatewayUserAssetAndCredential(t *testing.T, st *store.Store, targetAddr string) model.PlatformItem {
	t.Helper()
	userRec, err := st.CreatePlatformItem("users", model.PlatformItemRequest{
		Name:     "gateway-user",
		Type:     "local",
		Status:   "enabled",
		Password: "password123",
		Metadata: map[string]any{"role": "user"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	host, portText, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}
	port := mustAtoi(t, portText)
	assetRec, err := st.CreatePlatformItem("assets", model.PlatformItemRequest{
		Name:     "authorized-ssh",
		Status:   "enabled",
		Protocol: model.ProtocolSSH,
		Host:     host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	if _, err := st.CreatePlatformItem("credentials", model.PlatformItemRequest{
		Name:     "remote-password",
		Type:     string(model.CredentialSSHPassword),
		Status:   "encrypted",
		Username: "remote",
		Password: "target-secret",
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if _, err := st.CreatePlatformItem("authorized_assets", model.PlatformItemRequest{
		Name:     "gateway-user authorized ssh",
		Status:   "enabled",
		OwnerID:  userRec.ID,
		TargetID: assetRec.ID,
	}); err != nil {
		t.Fatalf("create authorization: %v", err)
	}
	return assetRec
}

func startTCPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

func assertEchoRoundTrip(t *testing.T, conn net.Conn, message string) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, message); err != nil {
		t.Fatalf("write echo message: %v", err)
	}
	buffer := make([]byte, len(message))
	if _, err := io.ReadFull(conn, buffer); err != nil {
		t.Fatalf("read echo message: %v", err)
	}
	if string(buffer) != message {
		t.Fatalf("echo response = %q, want %q", string(buffer), message)
	}
}

func startFakeSSHServer(t *testing.T, username, password string) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake target: %v", err)
	}
	signer := testSSHSigner(t)
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, payload []byte) (*ssh.Permissions, error) {
			if meta.User() == username && string(payload) == password {
				return nil, nil
			}
			return nil, errUnauthorized
		},
	}
	config.AddHostKey(signer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFakeSSHConn(conn, config)
		}
	}()
	return listener.Addr().String(), func() {
		_ = listener.Close()
		<-done
	}
}

var errUnauthorized = errors.New("unauthorized")

func handleFakeSSHConn(conn net.Conn, config *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer channel.Close()
			for req := range requests {
				switch req.Type {
				case "pty-req":
					replyRequest(req, true)
				case "shell":
					replyRequest(req, true)
					_, _ = channel.Write([]byte("target-shell\r\n"))
					_, _ = io.Copy(io.Discard, channel)
					return
				default:
					replyRequest(req, false)
				}
			}
		}()
	}
}

func newGatewayTestStore(t *testing.T) *store.Store {
	t.Helper()
	key := make([]byte, 32)
	cipher, err := security.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	dataDir := mustTempDir(t)
	st, err := store.Open(filepath.Join(dataDir, "store.json"), cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
		removeTempDir(dataDir)
	})
	return st
}

func testSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func testSSHHostKeyPEM(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), signer
}

func readUntilContains(t *testing.T, reader io.Reader, needle string, timeout time.Duration) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		var buffer bytes.Buffer
		chunk := make([]byte, 1024)
		for {
			n, err := reader.Read(chunk)
			if n > 0 {
				buffer.Write(chunk[:n])
				if strings.Contains(buffer.String(), needle) {
					done <- buffer.String()
					return
				}
			}
			if err != nil {
				done <- buffer.String()
				return
			}
		}
	}()
	select {
	case output := <-done:
		return output
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for %q", needle)
		return ""
	}
}

func mustAtoi(t *testing.T, value string) int {
	t.Helper()
	parsed, err := strconv.Atoi(value)
	if err != nil {
		t.Fatalf("parse int %q: %v", value, err)
	}
	return parsed
}

func mustTempDir(t *testing.T) string {
	t.Helper()
	path, err := os.MkdirTemp("", "openwebservermanager-gateway-*")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	return path
}

func removeTempDir(path string) {
	for i := 0; i < 10; i++ {
		if err := os.RemoveAll(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = os.RemoveAll(path)
}
