package sshsession

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
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

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
)

type GatewayConfig struct {
	Enabled        bool
	Address        string
	DataDir        string
	KnownHostsPath string
	Store          *store.Store
	Logger         *slog.Logger
}

type Gateway struct {
	cfg      GatewayConfig
	listener net.Listener
	done     chan struct{}
	once     sync.Once
}

type gatewayUser struct {
	UserID   string
	Username string
	Role     string
	IsAdmin  bool
}

type gatewayPTY struct {
	Term string
	Cols int
	Rows int
}

type ptyRequest struct {
	Term   string
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
	Modes  string
}

type windowChangeRequest struct {
	Cols   uint32
	Rows   uint32
	Width  uint32
	Height uint32
}

func GatewayConfigFromStore(st *store.Store, dataDir, overrideAddress string) GatewayConfig {
	cfg := GatewayConfig{
		Enabled:        strings.TrimSpace(overrideAddress) != "",
		Address:        strings.TrimSpace(overrideAddress),
		DataDir:        dataDir,
		KnownHostsPath: filepath.Join(dataDir, "known_hosts"),
		Store:          st,
	}
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0:2022"
	}
	if st == nil {
		return cfg
	}
	items, err := st.ListPlatformItems("ssh_gateways")
	if err != nil {
		return cfg
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		cfg.Enabled = true
		cfg.Address = gatewayListenAddress(item, cfg.Address)
		return cfg
	}
	return cfg
}

func StartGateway(ctx context.Context, cfg GatewayConfig) (*Gateway, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.Store == nil {
		return nil, errors.New("ssh gateway store is required")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if cfg.KnownHostsPath == "" {
		cfg.KnownHostsPath = filepath.Join(cfg.DataDir, "known_hosts")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Address == "" {
		cfg.Address = "0.0.0.0:2022"
	}
	signer, err := loadGatewayHostSigner(filepath.Join(cfg.DataDir, "ssh_gateway_host_key"))
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("listen ssh gateway %s: %w", cfg.Address, err)
	}
	gateway := &Gateway{cfg: cfg, listener: listener, done: make(chan struct{})}
	go gateway.serve(ctx, signer)
	return gateway, nil
}

func (g *Gateway) Address() string {
	if g == nil || g.listener == nil {
		return ""
	}
	return g.listener.Addr().String()
}

func (g *Gateway) Close() error {
	if g == nil {
		return nil
	}
	var err error
	g.once.Do(func() {
		err = g.listener.Close()
		<-g.done
	})
	return err
}

func (g *Gateway) serve(ctx context.Context, signer ssh.Signer) {
	defer close(g.done)
	serverConfig := &ssh.ServerConfig{PasswordCallback: g.passwordCallback}
	serverConfig.AddHostKey(signer)
	go func() {
		<-ctx.Done()
		_ = g.listener.Close()
	}()
	if g.cfg.Logger != nil {
		g.cfg.Logger.Info("ssh gateway listening", "addr", g.listener.Addr().String())
	}
	for {
		conn, err := g.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if g.cfg.Logger != nil {
				g.cfg.Logger.Warn("ssh gateway accept failed", "error", err)
			}
			continue
		}
		go g.handleConn(conn, serverConfig)
	}
}

func (g *Gateway) passwordCallback(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := strings.TrimSpace(meta.User())
	admin, ok, err := g.cfg.Store.VerifyAdmin(username, string(password))
	if err != nil {
		return nil, err
	}
	if !ok {
		admin, ok, err = g.cfg.Store.VerifyPlatformUser(username, string(password))
		if err != nil {
			return nil, err
		}
	}
	if !ok {
		return nil, errors.New("invalid username or password")
	}
	user := gatewayUser{
		UserID:   admin.UserID,
		Username: admin.Username,
		Role:     admin.Role,
		IsAdmin:  gatewayRoleIsAdmin(admin.Role),
	}
	_ = g.cfg.Store.RecordUserLogin(user.UserID, remoteIP(meta.RemoteAddr()), "ssh-gateway")
	_ = g.cfg.Store.Audit(model.AuditLog{UserID: user.UserID, Action: "ssh_gateway.login", TargetID: "ssh_gateway", Protocol: model.ProtocolSSH, Detail: "native ssh gateway login", ClientIP: remoteIP(meta.RemoteAddr())})
	return &ssh.Permissions{Extensions: map[string]string{
		"user_id":    user.UserID,
		"username":   user.Username,
		"role":       user.Role,
		"is_admin":   strconv.FormatBool(user.IsAdmin),
		"client_ip":  remoteIP(meta.RemoteAddr()),
		"login_time": time.Now().UTC().Format(time.RFC3339Nano),
	}}, nil
}

func (g *Gateway) handleConn(conn net.Conn, serverConfig *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go g.handleSessionChannel(sshConn, channel, requests)
	}
}

func (g *Gateway) handleSessionChannel(conn *ssh.ServerConn, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	pty := gatewayPTY{Term: "xterm-256color", Cols: 120, Rows: 32}
	var targetMu sync.Mutex
	var targetSession *ssh.Session
	started := make(chan struct{})
	var startOnce sync.Once

	startShell := func() {
		startOnce.Do(func() {
			close(started)
			target := g.runGatewayShell(conn, channel, pty)
			targetMu.Lock()
			targetSession = target
			targetMu.Unlock()
		})
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			var payload ptyRequest
			if err := ssh.Unmarshal(req.Payload, &payload); err == nil {
				pty.Term = valueOrDefault(payload.Term, pty.Term)
				if payload.Cols > 0 {
					pty.Cols = int(payload.Cols)
				}
				if payload.Rows > 0 {
					pty.Rows = int(payload.Rows)
				}
			}
			replyRequest(req, true)
		case "window-change":
			var payload windowChangeRequest
			if err := ssh.Unmarshal(req.Payload, &payload); err == nil && payload.Cols > 0 && payload.Rows > 0 {
				targetMu.Lock()
				if targetSession != nil {
					_ = targetSession.WindowChange(int(payload.Rows), int(payload.Cols))
				} else {
					pty.Cols = int(payload.Cols)
					pty.Rows = int(payload.Rows)
				}
				targetMu.Unlock()
			}
		case "shell":
			replyRequest(req, true)
			go startShell()
			<-started
		default:
			replyRequest(req, false)
		}
	}
}

func (g *Gateway) runGatewayShell(conn *ssh.ServerConn, channel ssh.Channel, pty gatewayPTY) *ssh.Session {
	user := userFromPermissions(conn.Permissions)
	assets, err := g.authorizedSSHAssets(user)
	if err != nil {
		_, _ = fmt.Fprintf(channel, "\r\nopenwebservermanager: %v\r\n", err)
		return nil
	}
	_, _ = fmt.Fprint(channel, "\r\nOpen Web Server Manager SSH Gateway\r\n")
	if len(assets) == 0 {
		_, _ = fmt.Fprint(channel, "No authorized SSH assets.\r\n")
		return nil
	}
	for index, asset := range assets {
		port := asset.Port
		if port == 0 {
			port = 22
		}
		_, _ = fmt.Fprintf(channel, "%d) %s  %s:%d\r\n", index+1, asset.Name, asset.Host, port)
	}
	_, _ = fmt.Fprint(channel, "Select asset number or id: ")
	choice, err := readGatewayLine(channel, 128)
	if err != nil {
		return nil
	}
	asset, ok := selectGatewayAsset(assets, choice)
	if !ok {
		_, _ = fmt.Fprint(channel, "\r\nInvalid asset selection.\r\n")
		return nil
	}
	credential, secret, ok, err := g.resolveSSHCredential(asset)
	if err != nil {
		_, _ = fmt.Fprintf(channel, "\r\nCredential error: %v\r\n", err)
		return nil
	}
	if !ok {
		_, _ = fmt.Fprint(channel, "\r\nNo compatible SSH credential found.\r\n")
		return nil
	}
	session, err := g.cfg.Store.CreateSession(model.ConnectionSession{
		Protocol:     model.ProtocolSSH,
		ServerID:     asset.ID,
		CredentialID: credential.ID,
		UserID:       user.UserID,
		ClientIP:     remoteIP(conn.RemoteAddr()),
		Width:        pty.Cols,
		Height:       pty.Rows,
	})
	if err != nil {
		_, _ = fmt.Fprintf(channel, "\r\nSession error: %v\r\n", err)
		return nil
	}
	_ = g.cfg.Store.Audit(model.AuditLog{UserID: user.UserID, Action: "ssh_gateway.connect", TargetID: asset.ID, Protocol: model.ProtocolSSH, Detail: "native ssh gateway selected asset " + asset.Name, ClientIP: remoteIP(conn.RemoteAddr())})
	_, _ = fmt.Fprintf(channel, "\r\nConnecting to %s...\r\n", asset.Name)
	targetSession, err := g.proxySSHSession(channel, session, asset, credential, secret, pty)
	if err != nil {
		now := time.Now().UTC()
		_, _ = g.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
			item.Status = model.SessionFailed
			item.Error = err.Error()
			item.EndedAt = &now
		})
		_, _ = fmt.Fprintf(channel, "\r\nConnection failed: %v\r\n", err)
		return nil
	}
	return targetSession
}

func (g *Gateway) proxySSHSession(channel ssh.Channel, session model.ConnectionSession, asset, credential model.PlatformItem, secret store.CredentialSecret, pty gatewayPTY) (*ssh.Session, error) {
	server := model.Server{ID: asset.ID, Name: asset.Name, Host: asset.Host, SSHPort: asset.Port, OS: model.ServerOSLinux}
	if server.SSHPort == 0 {
		server.SSHPort = 22
	}
	legacyCredential := model.Credential{
		ID:       credential.ID,
		Name:     credential.Name,
		Type:     model.CredentialType(credential.Type),
		Username: credential.Username,
	}
	client, err := dial(server, legacyCredential, secret, g.cfg.KnownHostsPath)
	if err != nil {
		return nil, err
	}
	targetSession, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	stdin, err := targetSession.StdinPipe()
	if err != nil {
		_ = targetSession.Close()
		_ = client.Close()
		return nil, err
	}
	stdout, err := targetSession.StdoutPipe()
	if err != nil {
		_ = targetSession.Close()
		_ = client.Close()
		return nil, err
	}
	stderr, err := targetSession.StderrPipe()
	if err != nil {
		_ = targetSession.Close()
		_ = client.Close()
		return nil, err
	}
	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := targetSession.RequestPty(pty.Term, pty.Rows, pty.Cols, modes); err != nil {
		_ = targetSession.Close()
		_ = client.Close()
		return nil, err
	}
	if err := targetSession.Shell(); err != nil {
		_ = targetSession.Close()
		_ = client.Close()
		return nil, err
	}
	_, _ = g.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
		item.Status = model.SessionActive
	})
	var once sync.Once
	closeAll := func(reason string) {
		once.Do(func() {
			_ = targetSession.Close()
			_ = client.Close()
			now := time.Now().UTC()
			_, _ = g.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
				item.Status = model.SessionClosed
				item.EndedAt = &now
				if reason != "" {
					item.Error = reason
				}
			})
		})
	}
	go copyNativeOutput(channel, session.ID, stdout, g.cfg.Store, closeAll)
	go copyNativeOutput(channel, session.ID, stderr, g.cfg.Store, closeAll)
	go copyNativeInput(channel, stdin, newCommandInterceptor(g.cfg.Store, session), closeAll)
	return targetSession, nil
}

func copyNativeOutput(channel ssh.Channel, sessionID string, reader io.Reader, st *store.Store, closeAll func(string)) {
	buf := make([]byte, 8192)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, writeErr := channel.Write(buf[:n]); writeErr != nil {
				closeAll(writeErr.Error())
				return
			}
			_, _ = st.UpdateSession(sessionID, func(item *model.ConnectionSession) {})
		}
		if err != nil {
			closeAll("")
			return
		}
	}
}

func copyNativeInput(channel ssh.Channel, writer io.Writer, interceptor *commandInterceptor, closeAll func(string)) {
	buf := make([]byte, 8192)
	for {
		n, err := channel.Read(buf)
		if n > 0 {
			filtered, events := interceptor.Process(buf[:n])
			for _, event := range events {
				if event.Blocked {
					_, _ = channel.Write([]byte(event.Notice))
				}
			}
			if len(filtered) > 0 {
				if _, writeErr := writer.Write(filtered); writeErr != nil {
					closeAll(writeErr.Error())
					return
				}
			}
		}
		if err != nil {
			closeAll("")
			return
		}
	}
}

func (g *Gateway) authorizedSSHAssets(user gatewayUser) ([]model.PlatformItem, error) {
	platform, err := g.cfg.Store.PlatformBootstrap()
	if err != nil {
		return nil, err
	}
	assets := []model.PlatformItem{}
	for _, asset := range platform["assets"] {
		if asset.Protocol != model.ProtocolSSH || !platformItemEnabled(asset) {
			continue
		}
		if user.IsAdmin || gatewayAssetAuthorized(platform, asset, user.UserID) {
			assets = append(assets, asset)
		}
	}
	return assets, nil
}

func (g *Gateway) resolveSSHCredential(asset model.PlatformItem) (model.PlatformItem, store.CredentialSecret, bool, error) {
	candidates := []string{}
	candidates = append(candidates, metadataStrings(asset.Metadata["credential_id"])...)
	candidates = append(candidates, metadataStrings(asset.Metadata["credential_ids"])...)
	for _, id := range candidates {
		credential, secret, ok, err := g.cfg.Store.GetPlatformCredentialSecret(strings.TrimSpace(id))
		if err != nil || !ok {
			return model.PlatformItem{}, store.CredentialSecret{}, false, err
		}
		if platformCredentialIsSSH(credential) && gatewayCredentialTargetsAsset(credential, asset, true) {
			return credential, secret, true, nil
		}
	}
	credentials, err := g.cfg.Store.ListPlatformItems("credentials")
	if err != nil {
		return model.PlatformItem{}, store.CredentialSecret{}, false, err
	}
	for _, credential := range credentials {
		if !platformCredentialIsSSH(credential) || !gatewayCredentialTargetsAsset(credential, asset, false) {
			continue
		}
		raw, secret, ok, err := g.cfg.Store.GetPlatformCredentialSecret(credential.ID)
		if err != nil || !ok {
			return model.PlatformItem{}, store.CredentialSecret{}, false, err
		}
		return raw, secret, true, nil
	}
	return model.PlatformItem{}, store.CredentialSecret{}, false, nil
}

func gatewayAssetAuthorized(platform map[string][]model.PlatformItem, asset model.PlatformItem, userID string) bool {
	userKeys := map[string]bool{}
	addGatewayAuthKeys(userKeys, userID)
	for _, user := range platform["users"] {
		if !gatewayAuthKeyMatches(userKeys, user.ID) {
			continue
		}
		addGatewayAuthKeys(userKeys, user.ID, user.Name, user.Username, user.OwnerID, user.ParentID, user.Group)
		addGatewayMetadataKeys(userKeys, user.Metadata, "department_id", "department_ids", "dept_id", "dept_ids", "group_id", "group_ids")
	}
	for _, authorization := range platform["authorized_assets"] {
		if !platformItemEnabled(authorization) || !gatewayAuthorizationSubjectMatches(authorization, userKeys) {
			continue
		}
		if gatewayAuthorizationTargetMatches(platform, authorization, asset) {
			return true
		}
	}
	return false
}

func gatewayAuthorizationSubjectMatches(authorization model.PlatformItem, userKeys map[string]bool) bool {
	keys := map[string]bool{}
	addGatewayAuthKeys(keys, authorization.OwnerID, authorization.Username, authorization.ParentID, authorization.Group)
	addGatewayMetadataKeys(keys, authorization.Metadata, "subject_id", "subject_ids", "user_id", "user_ids", "username", "usernames", "department_id", "department_ids", "dept_id", "dept_ids")
	return gatewayKeysOverlap(userKeys, keys)
}

func gatewayAuthorizationTargetMatches(platform map[string][]model.PlatformItem, authorization, asset model.PlatformItem) bool {
	targetKeys := map[string]bool{}
	addGatewayAuthKeys(targetKeys, authorization.TargetID, authorization.ParentID, authorization.Group)
	addGatewayMetadataKeys(targetKeys, authorization.Metadata, "target_id", "target_ids", "asset_id", "asset_ids", "asset_group_id", "asset_group_ids", "group_id", "group_ids", "group", "groups")
	if targetKeys["*"] {
		return true
	}
	assetKeys := map[string]bool{}
	addGatewayAuthKeys(assetKeys, asset.ID, asset.Name, asset.TargetID, asset.ParentID, asset.Group)
	addGatewayMetadataKeys(assetKeys, asset.Metadata, "asset_id", "asset_ids", "asset_group_id", "asset_group_ids", "group_id", "group_ids", "parent_id", "parent_ids")
	expandGatewayRelatedKeys(platform["asset_groups"], assetKeys)
	return gatewayKeysOverlap(assetKeys, targetKeys)
}

func expandGatewayRelatedKeys(items []model.PlatformItem, keys map[string]bool) {
	for {
		changed := false
		for _, item := range items {
			if !gatewayAuthKeyMatches(keys, item.ID) && !gatewayAuthKeyMatches(keys, item.Name) {
				continue
			}
			changed = addGatewayAuthKeys(keys, item.ID, item.Name, item.ParentID, item.Group) || changed
			changed = addGatewayMetadataKeys(keys, item.Metadata, "parent_id", "parent_ids", "group_id", "group_ids") || changed
		}
		if !changed {
			return
		}
	}
}

func platformCredentialIsSSH(credential model.PlatformItem) bool {
	credentialType := strings.ToLower(strings.TrimSpace(credential.Type))
	return credentialType == string(model.CredentialSSHPassword) || credentialType == string(model.CredentialSSHKey)
}

func gatewayCredentialTargetsAsset(credential, asset model.PlatformItem, strict bool) bool {
	if credential.TargetID == asset.ID || credential.TargetID == asset.Name {
		return true
	}
	for _, value := range metadataStrings(credential.Metadata["asset_id"]) {
		if value == asset.ID || value == asset.Name {
			return true
		}
	}
	for _, value := range metadataStrings(credential.Metadata["asset_ids"]) {
		for _, part := range splitCriteria(value) {
			if part == asset.ID || part == asset.Name {
				return true
			}
		}
	}
	return !strict && credential.TargetID == "" && len(metadataStrings(credential.Metadata["asset_id"])) == 0 && len(metadataStrings(credential.Metadata["asset_ids"])) == 0
}

func readGatewayLine(reader io.Reader, limit int) (string, error) {
	buffered := bufio.NewReader(reader)
	var out strings.Builder
	for out.Len() < limit {
		b, err := buffered.ReadByte()
		if err != nil {
			return "", err
		}
		switch b {
		case '\r', '\n':
			return strings.TrimSpace(out.String()), nil
		case 0x7f, 0x08:
			value := out.String()
			if len(value) > 0 {
				out.Reset()
				out.WriteString(value[:len(value)-1])
			}
		default:
			if b >= 0x20 {
				out.WriteByte(b)
			}
		}
	}
	return strings.TrimSpace(out.String()), nil
}

func selectGatewayAsset(assets []model.PlatformItem, choice string) (model.PlatformItem, bool) {
	choice = strings.TrimSpace(choice)
	if index, err := strconv.Atoi(choice); err == nil && index >= 1 && index <= len(assets) {
		return assets[index-1], true
	}
	for _, asset := range assets {
		if asset.ID == choice || strings.EqualFold(asset.Name, choice) {
			return asset, true
		}
	}
	return model.PlatformItem{}, false
}

func loadGatewayHostSigner(path string) (ssh.Signer, error) {
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("decode ssh gateway host key: no PEM block")
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ssh gateway host key: %w", err)
		}
		return ssh.NewSignerFromKey(key)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(privateKey)
}

func gatewayListenAddress(item model.PlatformItem, fallback string) string {
	host := strings.TrimSpace(item.Host)
	if host == "" {
		host = "0.0.0.0"
	}
	port := item.Port
	if port == 0 {
		port = 2022
	}
	if value := firstMetadataString(item.Metadata, "listen_address", "listen", "address"); value != "" {
		return value
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func userFromPermissions(permissions *ssh.Permissions) gatewayUser {
	if permissions == nil {
		return gatewayUser{}
	}
	isAdmin, _ := strconv.ParseBool(permissions.Extensions["is_admin"])
	return gatewayUser{
		UserID:   permissions.Extensions["user_id"],
		Username: permissions.Extensions["username"],
		Role:     permissions.Extensions["role"],
		IsAdmin:  isAdmin,
	}
}

func gatewayRoleIsAdmin(role string) bool {
	value := strings.ToLower(strings.TrimSpace(role))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value == "admin" || value == "administrator" || value == "super_admin" || value == "superadmin" || value == "root" || value == "owner"
}

func platformItemEnabled(item model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(item.Status))
	return status == "" || status == "enabled" || status == "active" || status == "online" || status == "encrypted"
}

func addGatewayMetadataKeys(keys map[string]bool, metadata map[string]any, names ...string) bool {
	changed := false
	for _, name := range names {
		for _, value := range metadataStrings(metadata[name]) {
			changed = addGatewayAuthKeys(keys, value) || changed
		}
	}
	return changed
}

func addGatewayAuthKeys(keys map[string]bool, values ...string) bool {
	changed := false
	for _, value := range values {
		for _, part := range splitCriteria(value) {
			key := strings.ToLower(strings.TrimSpace(part))
			if key == "" || keys[key] {
				continue
			}
			keys[key] = true
			changed = true
		}
	}
	return changed
}

func gatewayAuthKeyMatches(keys map[string]bool, value string) bool {
	for _, part := range splitCriteria(value) {
		if keys[strings.ToLower(strings.TrimSpace(part))] {
			return true
		}
	}
	return false
}

func gatewayKeysOverlap(left, right map[string]bool) bool {
	if left["*"] || right["*"] {
		return true
	}
	for key := range right {
		if left[key] {
			return true
		}
	}
	return false
}

func remoteIP(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

func replyRequest(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func firstMetadataString(metadata map[string]any, keys ...string) string {
	for _, key := range keys {
		values := metadataStrings(metadata[key])
		if len(values) == 0 {
			continue
		}
		value := strings.TrimSpace(values[0])
		if value != "" {
			return value
		}
	}
	return ""
}

func valueOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
