package sshsession

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

func TestGatewayConfigFromEnabledStoreItem(t *testing.T) {
	st := newGatewayTestStore(t)
	if _, err := st.CreatePlatformItem("ssh_gateways", model.PlatformItemRequest{
		Name:   "builtin",
		Status: "enabled",
		Host:   "127.0.0.1",
		Port:   22022,
	}); err != nil {
		t.Fatalf("create gateway item: %v", err)
	}
	cfg := GatewayConfigFromStore(st, t.TempDir(), "")
	if !cfg.Enabled || cfg.Address != "127.0.0.1:22022" {
		t.Fatalf("gateway config = %#v", cfg)
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
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"), cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
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
