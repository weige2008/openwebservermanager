package sshsession

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/roles"
	"openwebservermanager/internal/security"
	"openwebservermanager/internal/store"
)

type GatewayConfig struct {
	Enabled             bool
	Address             string
	DisablePasswordAuth bool
	HostKeyPEM          string
	DataDir             string
	KnownHostsPath      string
	Store               *store.Store
	Logger              *slog.Logger
}

type Gateway struct {
	cfg       GatewayConfig
	listener  net.Listener
	done      chan struct{}
	once      sync.Once
	failureMu sync.Mutex
}

type gatewayUser struct {
	UserID      string
	Username    string
	Role        string
	IsAdmin     bool
	DirectAsset string
}

type gatewayLoginRecord struct {
	Collection string
	ID         string
}

type gatewayLoginFailurePolicy struct {
	Threshold    int
	Window       time.Duration
	LockDuration time.Duration
}

type gatewayLoginFailure struct {
	Key         string    `json:"key"`
	Count       int       `json:"count"`
	LastFailure time.Time `json:"last_failure"`
	LockedUntil time.Time `json:"locked_until"`
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

type directTCPIPRequest struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func GatewayConfigFromStore(st *store.Store, dataDir, overrideAddress string) (GatewayConfig, error) {
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
		return cfg, nil
	}
	if privateKey, _, err := st.SystemSettingProxyPrivateKey(); err != nil {
		return cfg, err
	} else if strings.TrimSpace(privateKey) != "" {
		cfg.HostKeyPEM = strings.TrimSpace(privateKey)
	}
	settings, err := st.ListPlatformItems("system_settings")
	if err != nil {
		return cfg, err
	}
	for _, item := range settings {
		if !platformItemEnabled(item) || !strings.EqualFold(strings.TrimSpace(item.Type), "proxy") {
			continue
		}
		if enabled, ok := gatewayMetadataBool(item.Metadata["ssh_gateway_enabled"]); ok {
			cfg.Enabled = enabled
		}
		if address := firstMetadataString(item.Metadata, "ssh_listen_address", "ssh_gateway_listen_address"); address != "" {
			cfg.Address = address
		}
		for _, key := range []string{"ssh_disable_password_auth", "disable_password_auth", "disable_password_login"} {
			if disabled, ok := gatewayMetadataBool(item.Metadata[key]); ok {
				cfg.DisablePasswordAuth = disabled
				break
			}
		}
		break
	}
	items, err := st.ListPlatformItems("ssh_gateways")
	if err != nil {
		return cfg, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		cfg.Enabled = true
		cfg.Address = gatewayListenAddress(item, cfg.Address)
		if disabled, ok := gatewayDisablePasswordAuth(item); ok {
			cfg.DisablePasswordAuth = disabled
		}
		return cfg, nil
	}
	return cfg, nil
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
	signer, err := loadGatewaySigner(cfg)
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
	serverConfig := &ssh.ServerConfig{}
	if !g.cfg.DisablePasswordAuth {
		serverConfig.PasswordCallback = g.passwordCallback
	}
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
	username, directAsset := splitGatewayUsername(strings.TrimSpace(meta.User()))
	clientIP := remoteIP(meta.RemoteAddr())
	failureKey := clientIP + ":" + strings.ToLower(username)
	failurePolicy, err := g.gatewayLoginFailurePolicy()
	if err != nil {
		g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.failure_policy_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway failure policy: %w", err)
	}
	allowed, reason, err := g.gatewayLoginPolicyAllows(username, clientIP)
	if err != nil {
		g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.policy_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway login policy: %w", err)
	}
	if !allowed {
		if logErr := g.recordGatewayLoginDenied(meta, username, "policy", reason); logErr != nil {
			g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.denied_log.persist_failed", logErr)
			return nil, errors.Join(errors.New(reason), fmt.Errorf("persist denied login audit: %w", logErr))
		}
		return nil, errors.New(reason)
	}
	locked, reason, err := g.gatewayLoginLocked(username, clientIP)
	if err != nil {
		g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.lock_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway login lock: %w", err)
	}
	if locked {
		if logErr := g.recordGatewayLoginDenied(meta, username, "lock", reason); logErr != nil {
			g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.denied_log.persist_failed", logErr)
			return nil, errors.Join(errors.New(reason), fmt.Errorf("persist denied login audit: %w", logErr))
		}
		return nil, errors.New(reason)
	}
	if retryAfter, locked, err := g.gatewayRuntimeLoginLocked(failureKey, failurePolicy); err != nil {
		g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.failure_state_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway login failure state: %w", err)
	} else if locked {
		reason := "too many failed login attempts; retry after " + retryAfter.Round(time.Second).String()
		if logErr := g.recordGatewayLoginDenied(meta, username, "lock", reason); logErr != nil {
			g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.denied_log.persist_failed", logErr)
			return nil, errors.Join(errors.New(reason), fmt.Errorf("persist denied login audit: %w", logErr))
		}
		return nil, errors.New(reason)
	}
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
		authErr := errors.New("invalid username or password")
		if logErr := g.recordGatewayLoginFailure(meta, username, authErr.Error()); logErr != nil {
			g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.failed_log.persist_failed", logErr)
			return nil, errors.Join(authErr, fmt.Errorf("persist failed login audit: %w", logErr))
		}
		if _, failureErr := g.gatewayRecordLoginFailure(failureKey, username, clientIP, failurePolicy); failureErr != nil {
			g.auditGatewayLoginFailure(meta, username, "ssh_gateway.login.failure_state.persist_failed", failureErr)
			return nil, errors.Join(authErr, fmt.Errorf("persist login failure state: %w", failureErr))
		}
		return nil, authErr
	}
	user := gatewayUser{
		UserID:      admin.UserID,
		Username:    admin.Username,
		Role:        admin.Role,
		IsAdmin:     gatewayRoleIsAdmin(admin.Role),
		DirectAsset: directAsset,
	}
	forceMFA, err := g.gatewayForceMFAEnabled()
	if err != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.mfa_policy_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway MFA policy: %w", err)
	}
	profile, profileExists, err := g.cfg.Store.UserMFAProfile(user.UserID)
	if err != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.mfa_profile_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway MFA profile: %w", err)
	}
	if forceMFA || (profileExists && profile.Enabled) {
		if !profileExists || !profile.Enabled || strings.TrimSpace(profile.Secret) == "" {
			reason := "MFA registration is required; enroll MFA in the web console before using the SSH gateway"
			if logErr := g.recordGatewayLoginDenied(meta, user.Username, "mfa", reason); logErr != nil {
				g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.mfa_denied_log.persist_failed", logErr)
				return nil, errors.Join(errors.New(reason), fmt.Errorf("persist MFA denial audit: %w", logErr))
			}
			return nil, &ssh.BannerError{Err: errors.New(reason), Message: reason + "\n"}
		}
		return nil, &ssh.PartialSuccessError{Next: ssh.ServerAuthCallbacks{
			KeyboardInteractiveCallback: func(nextMeta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
				return g.keyboardInteractiveMFACallback(nextMeta, challenge, user, profile, failureKey, failurePolicy)
			},
		}}
	}
	return g.completeGatewayLogin(meta, user, failureKey)
}

func (g *Gateway) keyboardInteractiveMFACallback(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge, user gatewayUser, profile store.MFAProfile, failureKey string, failurePolicy gatewayLoginFailurePolicy) (*ssh.Permissions, error) {
	clientIP := remoteIP(meta.RemoteAddr())
	if locked, reason, err := g.gatewayLoginLocked(user.Username, clientIP); err != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.lock_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway login lock: %w", err)
	} else if locked {
		return nil, errors.New(reason)
	}
	if retryAfter, locked, err := g.gatewayRuntimeLoginLocked(failureKey, failurePolicy); err != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.failure_state_load_failed", err)
		return nil, fmt.Errorf("load ssh gateway login failure state: %w", err)
	} else if locked {
		return nil, fmt.Errorf("too many failed login attempts; retry after %s", retryAfter.Round(time.Second))
	}
	answers, err := challenge(user.Username, "Multi-factor authentication is required.", []string{"Verification code or recovery code: "}, []bool{false})
	if err != nil {
		return nil, fmt.Errorf("request SSH gateway MFA response: %w", err)
	}
	if len(answers) != 1 {
		return g.rejectGatewayMFA(meta, user, failureKey, failurePolicy, "invalid MFA response")
	}
	code := strings.TrimSpace(answers[0])
	method := "totp"
	verified := security.VerifyTOTP(profile.Secret, code, time.Now().UTC())
	if !verified {
		method = "recovery_code"
		verified, err = g.cfg.Store.ConsumeUserMFARecoveryCode(user.UserID, code)
		if err != nil {
			g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.mfa_recovery.persist_failed", err)
			return nil, fmt.Errorf("consume SSH gateway MFA recovery code: %w", err)
		}
	}
	if !verified {
		return g.rejectGatewayMFA(meta, user, failureKey, failurePolicy, "invalid MFA code")
	}
	permissions, err := g.completeGatewayLogin(meta, user, failureKey)
	if err != nil {
		return nil, err
	}
	permissions.Extensions["mfa_method"] = method
	return permissions, nil
}

func (g *Gateway) rejectGatewayMFA(meta ssh.ConnMetadata, user gatewayUser, failureKey string, failurePolicy gatewayLoginFailurePolicy, detail string) (*ssh.Permissions, error) {
	authErr := errors.New(detail)
	if logErr := g.recordGatewayMFAFailure(meta, user, detail); logErr != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.mfa_failed_log.persist_failed", logErr)
		return nil, errors.Join(authErr, fmt.Errorf("persist failed MFA audit: %w", logErr))
	}
	if _, failureErr := g.gatewayRecordLoginFailure(failureKey, user.Username, remoteIP(meta.RemoteAddr()), failurePolicy); failureErr != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.failure_state.persist_failed", failureErr)
		return nil, errors.Join(authErr, fmt.Errorf("persist login failure state: %w", failureErr))
	}
	return nil, authErr
}

func (g *Gateway) completeGatewayLogin(meta ssh.ConnMetadata, user gatewayUser, failureKey string) (*ssh.Permissions, error) {
	if err := g.gatewayResetLoginFailure(failureKey); err != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.failure_state.reset_failed", err)
		return nil, fmt.Errorf("reset ssh gateway login failure state: %w", err)
	}
	if err := g.recordGatewayLogin(meta, user); err != nil {
		g.auditGatewayLoginFailure(meta, user.UserID, "ssh_gateway.login.persist_failed", err)
		return nil, fmt.Errorf("persist ssh gateway login: %w", err)
	}
	return &ssh.Permissions{Extensions: map[string]string{
		"user_id":      user.UserID,
		"username":     user.Username,
		"role":         user.Role,
		"is_admin":     strconv.FormatBool(user.IsAdmin),
		"client_ip":    remoteIP(meta.RemoteAddr()),
		"login_time":   time.Now().UTC().Format(time.RFC3339Nano),
		"direct_asset": user.DirectAsset,
	}}, nil
}

func (g *Gateway) gatewayForceMFAEnabled() (bool, error) {
	items, err := g.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return false, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "security" && itemType != "identity" && itemType != "access" && itemType != "mfa" {
			continue
		}
		for _, key := range []string{"force_mfa", "forceMFA", "mfa_required", "require_mfa", "access_mfa"} {
			if enabled, ok := gatewayMetadataBool(item.Metadata[key]); ok && enabled {
				return true, nil
			}
		}
	}
	return false, nil
}

func (g *Gateway) recordGatewayLogin(meta ssh.ConnMetadata, user gatewayUser) error {
	if g == nil || g.cfg.Store == nil {
		return errors.New("gateway login store is unavailable")
	}
	clientIP := remoteIP(meta.RemoteAddr())
	loginLog, err := g.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        user.Username,
		Type:        "ssh_gateway",
		Status:      "success",
		OwnerID:     user.UserID,
		Description: "signed in to native ssh gateway",
		Metadata: map[string]any{
			"client_ip":  clientIP,
			"account":    user.Username,
			"user_agent": "ssh-gateway",
		},
	})
	if err != nil {
		return fmt.Errorf("create gateway login log: %w", err)
	}
	operationLog, err := g.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "ssh_gateway.login",
		Type:        "ssh_gateway",
		Status:      "recorded",
		Protocol:    model.ProtocolSSH,
		OwnerID:     user.UserID,
		TargetID:    "ssh_gateway",
		Description: "native ssh gateway login",
		Metadata: map[string]any{
			"client_ip": clientIP,
			"account":   user.Username,
		},
	})
	if err != nil {
		return errors.Join(fmt.Errorf("create gateway operation log: %w", err), g.rollbackGatewayLoginRecords(meta, user.UserID, gatewayLoginRecord{Collection: "login_logs", ID: loginLog.ID}))
	}
	if err := g.cfg.Store.RecordUserLogin(user.UserID, clientIP, "ssh-gateway"); err != nil {
		return errors.Join(fmt.Errorf("record gateway user login state: %w", err), g.rollbackGatewayLoginRecords(meta, user.UserID,
			gatewayLoginRecord{Collection: "operation_logs", ID: operationLog.ID},
			gatewayLoginRecord{Collection: "login_logs", ID: loginLog.ID},
		))
	}
	return nil
}

func (g *Gateway) recordGatewayLoginFailure(meta ssh.ConnMetadata, username, detail string) error {
	if g == nil || g.cfg.Store == nil {
		return errors.New("gateway login store is unavailable")
	}
	_, err := g.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        username,
		Type:        "ssh_gateway",
		Status:      "failed",
		Description: detail,
		Metadata: map[string]any{
			"client_ip":  remoteIP(meta.RemoteAddr()),
			"account":    username,
			"user_agent": "ssh-gateway",
		},
	})
	return err
}

func (g *Gateway) recordGatewayMFAFailure(meta ssh.ConnMetadata, user gatewayUser, detail string) error {
	if g == nil || g.cfg.Store == nil {
		return errors.New("gateway login store is unavailable")
	}
	_, err := g.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        user.Username,
		Type:        "mfa",
		Status:      "failed",
		OwnerID:     user.UserID,
		Description: detail,
		Metadata: map[string]any{
			"client_ip":  remoteIP(meta.RemoteAddr()),
			"account":    user.Username,
			"user_agent": "ssh-gateway",
		},
	})
	return err
}

func (g *Gateway) recordGatewayLoginDenied(meta ssh.ConnMetadata, username, denialType, detail string) error {
	if g == nil || g.cfg.Store == nil {
		return errors.New("gateway login store is unavailable")
	}
	_, err := g.cfg.Store.CreatePlatformItem("login_logs", model.PlatformItemRequest{
		Name:        username,
		Type:        denialType,
		Status:      "denied",
		Description: detail,
		Metadata: map[string]any{
			"client_ip":  remoteIP(meta.RemoteAddr()),
			"account":    username,
			"user_agent": "ssh-gateway",
		},
	})
	return err
}

func (g *Gateway) gatewayLoginPolicyAllows(username, clientIP string) (bool, string, error) {
	policies, err := g.cfg.Store.ListPlatformItems("login_policies")
	if err != nil {
		return false, "", err
	}
	now := time.Now().UTC()
	active := make([]model.PlatformItem, 0, len(policies))
	for _, policy := range policies {
		if !platformItemEnabled(policy) || gatewayLoginPolicyExpired(policy, now) {
			continue
		}
		active = append(active, policy)
	}
	sort.SliceStable(active, func(i, j int) bool {
		left, right := gatewayLoginPolicyPriority(active[i]), gatewayLoginPolicyPriority(active[j])
		if left != right {
			return left > right
		}
		if !active[i].CreatedAt.Equal(active[j].CreatedAt) {
			return active[i].CreatedAt.Before(active[j].CreatedAt)
		}
		return active[i].ID < active[j].ID
	})
	hasAllowPolicy := false
	highestMatchedPriority := 0
	hasMatch := false
	matched := []model.PlatformItem{}
	for _, policy := range active {
		if gatewayLoginPolicyAction(policy) == "allow" && gatewayLoginAccountMatches(policy, username) {
			hasAllowPolicy = true
		}
		if !gatewayLoginPolicyMatches(policy, username, clientIP) {
			continue
		}
		priority := gatewayLoginPolicyPriority(policy)
		if !hasMatch {
			hasMatch = true
			highestMatchedPriority = priority
		}
		if priority != highestMatchedPriority {
			break
		}
		matched = append(matched, policy)
	}
	for _, policy := range matched {
		action := gatewayLoginPolicyAction(policy)
		if action == "deny" || action == "reject" || action == "block" {
			return false, "blocked by login policy " + policy.Name, nil
		}
	}
	if hasMatch {
		return true, "", nil
	}
	if hasAllowPolicy {
		return false, "no allow login policy matched", nil
	}
	return true, "", nil
}

func (g *Gateway) gatewayLoginLocked(username, clientIP string) (bool, string, error) {
	locks, err := g.cfg.Store.ListPlatformItems("login_locks")
	if err != nil {
		return false, "", err
	}
	now := time.Now().UTC()
	for _, lock := range locks {
		if !gatewayLoginLockEnabled(lock) {
			continue
		}
		until, hasExpiry := gatewayMetadataTime(lock.Metadata["locked_until"])
		if hasExpiry && !now.Before(until) {
			if err := g.cfg.Store.DeletePlatformItem("login_locks", lock.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
				return false, "", err
			}
			continue
		}
		if gatewayLoginAccountMatches(lock, username) && gatewayLoginIPCriteriaMatches(append([]string{lock.Host}, metadataStrings(lock.Metadata["client_ip"])...), clientIP) {
			return true, "account or client ip is locked", nil
		}
	}
	return false, "", nil
}

func (g *Gateway) gatewayLoginFailurePolicy() (gatewayLoginFailurePolicy, error) {
	policy := gatewayLoginFailurePolicy{Threshold: 5, Window: 15 * time.Minute, LockDuration: 5 * time.Minute}
	items, err := g.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return policy, err
	}
	for _, item := range items {
		if !platformItemEnabled(item) {
			continue
		}
		itemType := strings.ToLower(strings.TrimSpace(item.Type))
		if itemType != "security" && itemType != "identity" && itemType != "login" && itemType != "password" && itemType != "mfa" {
			continue
		}
		if value, ok := gatewayMetadataIntByKeys(item.Metadata, "login_failure_threshold", "failure_threshold", "max_login_failures", "login_lock_threshold", "lock_threshold"); ok {
			policy.Threshold = gatewayClampInt(value, 1, 50, 5)
		}
		if value, ok := gatewayMetadataIntByKeys(item.Metadata, "login_failure_window_minutes", "failure_window_minutes", "login_lock_window_minutes", "lock_window_minutes"); ok {
			policy.Window = time.Duration(gatewayClampInt(value, 1, 1440, 15)) * time.Minute
		}
		if value, ok := gatewayMetadataIntByKeys(item.Metadata, "login_lock_minutes", "lock_minutes", "login_lock_duration_minutes", "lock_duration_minutes"); ok {
			policy.LockDuration = time.Duration(gatewayClampInt(value, 1, 1440, 5)) * time.Minute
		}
	}
	return policy, nil
}

func (g *Gateway) gatewayRuntimeLoginLocked(key string, policy gatewayLoginFailurePolicy) (time.Duration, bool, error) {
	g.failureMu.Lock()
	defer g.failureMu.Unlock()
	failure, ok, err := g.gatewayLoadLoginFailure(key)
	if err != nil {
		return 0, false, err
	}
	now := time.Now().UTC()
	if !failure.LockedUntil.IsZero() && now.Before(failure.LockedUntil) {
		return time.Until(failure.LockedUntil), true, nil
	}
	if ok && !failure.LastFailure.IsZero() && now.Sub(failure.LastFailure) > policy.Window {
		if err := g.gatewayResetLoginFailureUnlocked(key); err != nil {
			return 0, false, err
		}
	}
	return 0, false, nil
}

func (g *Gateway) gatewayRecordLoginFailure(key, username, clientIP string, policy gatewayLoginFailurePolicy) (gatewayLoginFailure, error) {
	g.failureMu.Lock()
	defer g.failureMu.Unlock()
	failure, hadPrevious, err := g.gatewayLoadLoginFailure(key)
	if err != nil {
		return gatewayLoginFailure{}, err
	}
	previous := failure
	now := time.Now().UTC()
	if !failure.LastFailure.IsZero() && now.Sub(failure.LastFailure) > policy.Window {
		failure = gatewayLoginFailure{Key: key}
	}
	failure.Key = key
	failure.Count++
	failure.LastFailure = now
	if failure.Count >= policy.Threshold {
		failure.LockedUntil = now.Add(policy.LockDuration)
	}
	expiresAt := failure.LastFailure.Add(policy.Window)
	if failure.LockedUntil.After(expiresAt) {
		expiresAt = failure.LockedUntil
	}
	payload, err := json.Marshal(failure)
	if err != nil {
		return gatewayLoginFailure{}, err
	}
	_, err = g.cfg.Store.SavePlatformItem("login_failure_states", model.PlatformItem{
		ID:     gatewayLoginFailureRecordID(key),
		Name:   "login_failure_states",
		Type:   "auth-runtime",
		Status: "active",
		Metadata: map[string]any{
			"payload":    string(payload),
			"expires_at": expiresAt.UTC().Format(time.RFC3339Nano),
		},
	})
	if err != nil {
		return gatewayLoginFailure{}, err
	}
	if !failure.LockedUntil.IsZero() {
		if err := g.gatewayCreateLoginLock(username, clientIP, failure); err != nil {
			rollbackErr := g.gatewayRestoreLoginFailure(key, previous, hadPrevious, policy)
			if rollbackErr != nil {
				return gatewayLoginFailure{}, errors.Join(err, fmt.Errorf("restore previous login failure state: %w", rollbackErr))
			}
			return gatewayLoginFailure{}, err
		}
	}
	return failure, nil
}

func (g *Gateway) gatewayRestoreLoginFailure(key string, previous gatewayLoginFailure, existed bool, policy gatewayLoginFailurePolicy) error {
	if !existed {
		if err := g.cfg.Store.DeletePlatformItem("login_failure_states", gatewayLoginFailureRecordID(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	expiresAt := previous.LastFailure.Add(policy.Window)
	if previous.LockedUntil.After(expiresAt) {
		expiresAt = previous.LockedUntil
	}
	payload, err := json.Marshal(previous)
	if err != nil {
		return err
	}
	_, err = g.cfg.Store.SavePlatformItem("login_failure_states", model.PlatformItem{
		ID:     gatewayLoginFailureRecordID(key),
		Name:   "login_failure_states",
		Type:   "auth-runtime",
		Status: "active",
		Metadata: map[string]any{
			"payload":    string(payload),
			"expires_at": expiresAt.UTC().Format(time.RFC3339Nano),
		},
	})
	return err
}

func (g *Gateway) gatewayLoadLoginFailure(key string) (gatewayLoginFailure, bool, error) {
	item, ok, err := g.cfg.Store.GetPlatformItem("login_failure_states", gatewayLoginFailureRecordID(key))
	if err != nil || !ok {
		return gatewayLoginFailure{}, ok, err
	}
	if expiresAt, ok := gatewayMetadataTime(item.Metadata["expires_at"]); ok && !time.Now().UTC().Before(expiresAt) {
		if err := g.cfg.Store.DeletePlatformItem("login_failure_states", item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return gatewayLoginFailure{}, false, err
		}
		return gatewayLoginFailure{}, false, nil
	}
	payload, _ := item.Metadata["payload"].(string)
	if strings.TrimSpace(payload) == "" {
		return gatewayLoginFailure{}, false, errors.New("persisted login failure state is missing payload")
	}
	var failure gatewayLoginFailure
	if err := json.Unmarshal([]byte(payload), &failure); err != nil {
		return gatewayLoginFailure{}, false, fmt.Errorf("decode login failure state: %w", err)
	}
	return failure, true, nil
}

func (g *Gateway) gatewayResetLoginFailure(key string) error {
	g.failureMu.Lock()
	defer g.failureMu.Unlock()
	return g.gatewayResetLoginFailureUnlocked(key)
}

func (g *Gateway) gatewayResetLoginFailureUnlocked(key string) error {
	if err := g.cfg.Store.DeletePlatformItem("login_failure_states", gatewayLoginFailureRecordID(key)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (g *Gateway) gatewayCreateLoginLock(username, clientIP string, failure gatewayLoginFailure) error {
	_, err := g.cfg.Store.CreatePlatformItem("login_locks", model.PlatformItemRequest{
		Name:        username,
		Type:        "password",
		Status:      "locked",
		Username:    username,
		Host:        clientIP,
		Description: "too many failed login attempts",
		Metadata: map[string]any{
			"account":       username,
			"client_ip":     clientIP,
			"failure_count": failure.Count,
			"locked_until":  failure.LockedUntil.UTC(),
			"last_failure":  failure.LastFailure.UTC(),
			"source":        "ssh_gateway",
		},
	})
	return err
}

func gatewayLoginFailureRecordID(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func gatewayMetadataIntByKeys(metadata map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		if value, ok := gatewayMetadataInt(metadata[key]); ok {
			return value, true
		}
	}
	return 0, false
}

func gatewayClampInt(value, minimum, maximum, fallback int) int {
	if value < minimum || value > maximum {
		return fallback
	}
	return value
}

func gatewayLoginLockEnabled(lock model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(lock.Status))
	return status == "" || status == "enabled" || status == "active" || status == "locked"
}

func gatewayLoginPolicyPriority(policy model.PlatformItem) int {
	for _, key := range []string{"priority", "order", "sort", "weight"} {
		if value, ok := gatewayMetadataInt(policy.Metadata[key]); ok {
			return value
		}
	}
	return 0
}

func gatewayLoginPolicyExpired(policy model.PlatformItem, now time.Time) bool {
	for _, key := range []string{"expires_at", "expire_at", "expiresAt", "expired_at", "valid_until", "not_after"} {
		if expiresAt, ok := gatewayMetadataTime(policy.Metadata[key]); ok {
			return !now.Before(expiresAt)
		}
	}
	return false
}

func gatewayLoginPolicyAction(policy model.PlatformItem) string {
	action := strings.ToLower(strings.TrimSpace(policy.Type))
	if value := firstMetadataString(policy.Metadata, "action"); value != "" {
		action = strings.ToLower(value)
	}
	if action == "" {
		return "allow"
	}
	return action
}

func gatewayLoginPolicyMatches(policy model.PlatformItem, username, clientIP string) bool {
	if !gatewayLoginAccountMatches(policy, username) {
		return false
	}
	values := []string{policy.Host, policy.TargetID, policy.Group}
	for _, key := range []string{"ip", "cidr", "ip_range", "client_ip", "ips"} {
		values = append(values, metadataStrings(policy.Metadata[key])...)
	}
	return gatewayLoginIPCriteriaMatches(values, clientIP)
}

func gatewayLoginAccountMatches(item model.PlatformItem, username string) bool {
	candidates := []string{item.Username}
	candidates = append(candidates, metadataStrings(item.Metadata["account"])...)
	candidates = append(candidates, metadataStrings(item.Metadata["username"])...)
	hasCriteria := false
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		hasCriteria = true
		if candidate == "*" || strings.EqualFold(candidate, username) {
			return true
		}
	}
	return !hasCriteria
}

func gatewayLoginIPCriteriaMatches(values []string, clientIP string) bool {
	hasCriteria := false
	for _, value := range values {
		for _, criterion := range splitCriteria(value) {
			hasCriteria = true
			if criterion == "*" || criterion == "0.0.0.0/0" || gatewayLoginIPMatches(criterion, clientIP) {
				return true
			}
		}
	}
	return !hasCriteria
}

func gatewayLoginIPMatches(pattern, clientIP string) bool {
	pattern = strings.TrimSpace(pattern)
	clientIP = strings.TrimSpace(clientIP)
	if pattern == clientIP {
		return true
	}
	if _, network, err := net.ParseCIDR(pattern); err == nil {
		ip := net.ParseIP(clientIP)
		return ip != nil && network.Contains(ip)
	}
	return false
}

func gatewayMetadataInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return 0, false
	}
}

func (g *Gateway) rollbackGatewayLoginRecords(meta ssh.ConnMetadata, userID string, records ...gatewayLoginRecord) error {
	var rollbackErr error
	for _, record := range records {
		if strings.TrimSpace(record.Collection) == "" || strings.TrimSpace(record.ID) == "" {
			continue
		}
		if err := g.cfg.Store.DeletePlatformItem(record.Collection, record.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	if rollbackErr != nil {
		g.auditGatewayLoginFailure(meta, userID, "ssh_gateway.login.rollback_failed", rollbackErr)
	}
	return rollbackErr
}

func (g *Gateway) auditGatewayLoginFailure(meta ssh.ConnMetadata, userID, action string, err error) {
	if g == nil || g.cfg.Store == nil || err == nil {
		return
	}
	_ = g.cfg.Store.Audit(model.AuditLog{
		UserID:   userID,
		Action:   action,
		TargetID: "ssh_gateway",
		Protocol: model.ProtocolSSH,
		Detail:   err.Error(),
		ClientIP: remoteIP(meta.RemoteAddr()),
	})
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
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				continue
			}
			go g.handleSessionChannel(sshConn, channel, requests)
		case "direct-tcpip":
			go g.handleDirectTCPIP(sshConn, newChannel)
		default:
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session and direct-tcpip channels are supported")
			continue
		}
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
	var asset model.PlatformItem
	if user.DirectAsset != "" {
		var ok bool
		asset, ok = selectGatewayAsset(assets, user.DirectAsset)
		if !ok {
			_, _ = fmt.Fprintf(channel, "Direct asset %q is not authorized or does not exist.\r\n", user.DirectAsset)
			return nil
		}
	} else {
		for index, item := range assets {
			port := item.Port
			if port == 0 {
				port = 22
			}
			_, _ = fmt.Fprintf(channel, "%d) %s  %s:%d\r\n", index+1, item.Name, item.Host, port)
		}
		_, _ = fmt.Fprint(channel, "Select asset number or id: ")
		choice, err := readGatewayLine(channel, 128)
		if err != nil {
			return nil
		}
		var ok bool
		asset, ok = selectGatewayAsset(assets, choice)
		if !ok {
			_, _ = fmt.Fprint(channel, "\r\nInvalid asset selection.\r\n")
			return nil
		}
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
	if err := g.recordGatewayConnection(conn, user, session, asset); err != nil {
		if rollbackErr := g.cfg.Store.DeleteSession(session.ID); rollbackErr != nil {
			g.auditGatewayConnectionFailure(conn, user, session, asset, "ssh_gateway.connect.rollback_failed", rollbackErr)
			err = errors.Join(err, fmt.Errorf("roll back unaudited session: %w", rollbackErr))
		}
		g.auditGatewayConnectionFailure(conn, user, session, asset, "ssh_gateway.connect.log.persist_failed", err)
		_, _ = fmt.Fprintf(channel, "\r\nSession error: connection audit is unavailable: %v\r\n", err)
		return nil
	}
	_, _ = fmt.Fprintf(channel, "\r\nConnecting to %s...\r\n", asset.Name)
	targetSession, err := g.proxySSHSession(channel, session, asset, credential, secret, pty)
	if err != nil {
		now := time.Now().UTC()
		if _, stateErr := g.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
			item.Status = model.SessionFailed
			item.Error = err.Error()
			item.EndedAt = &now
		}); stateErr != nil {
			g.auditGatewayConnectionFailure(conn, user, session, asset, "ssh_gateway.session.failure_state.persist_failed", stateErr)
			err = errors.Join(err, fmt.Errorf("persist failed session state: %w", stateErr))
		}
		_, _ = fmt.Fprintf(channel, "\r\nConnection failed: %v\r\n", err)
		return nil
	}
	return targetSession
}

func (g *Gateway) recordGatewayConnection(conn *ssh.ServerConn, user gatewayUser, session model.ConnectionSession, asset model.PlatformItem) error {
	if g == nil || g.cfg.Store == nil {
		return errors.New("gateway connection audit store is unavailable")
	}
	_, err := g.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "ssh_gateway.connect",
		Type:        "ssh_gateway",
		Status:      "started",
		Protocol:    model.ProtocolSSH,
		OwnerID:     user.UserID,
		TargetID:    asset.ID,
		Description: "native ssh gateway selected asset " + asset.Name,
		Metadata: map[string]any{
			"client_ip":     remoteIP(conn.RemoteAddr()),
			"session_id":    session.ID,
			"credential_id": session.CredentialID,
		},
	})
	return err
}

func (g *Gateway) auditGatewayConnectionFailure(conn *ssh.ServerConn, user gatewayUser, session model.ConnectionSession, asset model.PlatformItem, action string, err error) {
	if g == nil || g.cfg.Store == nil || err == nil {
		return
	}
	_ = g.cfg.Store.Audit(model.AuditLog{
		UserID:   user.UserID,
		Action:   action,
		TargetID: asset.ID,
		Protocol: model.ProtocolSSH,
		Detail:   "session " + session.ID + ": " + err.Error(),
		ClientIP: remoteIP(conn.RemoteAddr()),
	})
}

func (g *Gateway) handleDirectTCPIP(conn *ssh.ServerConn, newChannel ssh.NewChannel) {
	user := userFromPermissions(conn.Permissions)
	var req directTCPIPRequest
	if err := ssh.Unmarshal(newChannel.ExtraData(), &req); err != nil {
		_ = newChannel.Reject(ssh.ConnectionFailed, "invalid direct-tcpip request")
		return
	}
	host := strings.TrimSpace(req.Host)
	port := int(req.Port)
	if host == "" || port <= 0 || port > 65535 {
		_ = newChannel.Reject(ssh.Prohibited, "invalid target")
		return
	}
	dialHost, dialPort, allowed, reason := g.forwardAllowed(user, host, port)
	if !allowed {
		if err := g.auditForward(conn, user, host, port, "denied", reason); err != nil {
			g.auditForwardPersistFailure(conn, user, host, port, "denied", err)
		}
		_ = newChannel.Reject(ssh.Prohibited, reason)
		return
	}
	if err := g.auditForward(conn, user, host, port, "started", "direct-tcpip"); err != nil {
		g.auditForwardPersistFailure(conn, user, host, port, "started", err)
		_ = newChannel.Reject(ssh.Prohibited, "forwarding audit is unavailable")
		return
	}
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(dialHost, strconv.Itoa(dialPort)), 15*time.Second)
	if err != nil {
		if auditErr := g.auditForward(conn, user, host, port, "failed", err.Error()); auditErr != nil {
			g.auditForwardPersistFailure(conn, user, host, port, "failed", auditErr)
		}
		_ = newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		_ = upstream.Close()
		if auditErr := g.auditForward(conn, user, host, port, "failed", "accept direct-tcpip channel: "+err.Error()); auditErr != nil {
			g.auditForwardPersistFailure(conn, user, host, port, "failed", auditErr)
		}
		return
	}
	go ssh.DiscardRequests(requests)
	go proxyTCPChannel(channel, upstream, func() {
		if err := g.auditForward(conn, user, host, port, "closed", "direct-tcpip"); err != nil {
			g.auditForwardPersistFailure(conn, user, host, port, "closed", err)
		}
	})
}

func (g *Gateway) forwardAllowed(user gatewayUser, host string, port int) (string, int, bool, string) {
	normalizedHost := normalizeForwardHost(host)
	if normalizedHost == "" || port <= 0 || port > 65535 {
		return "", 0, false, "invalid target"
	}
	assets, err := g.authorizedSSHAssets(user)
	if err != nil {
		return "", 0, false, err.Error()
	}
	for _, asset := range assets {
		assetPort := asset.Port
		if assetPort == 0 {
			assetPort = 22
		}
		if assetPort != port {
			continue
		}
		if forwardHostMatchesAsset(normalizedHost, asset) {
			if strings.TrimSpace(asset.Host) == "" {
				return "", 0, false, "asset target has no host"
			}
			return strings.TrimSpace(asset.Host), assetPort, true, "authorized asset"
		}
	}
	for _, rule := range g.forwardAllowlistRules() {
		if forwardRuleMatches(rule, normalizedHost, port) {
			return normalizedHost, port, true, "allowlist"
		}
	}
	return "", 0, false, "target is not authorized by asset grants or forwarding allowlist"
}

func (g *Gateway) forwardAllowlistRules() []string {
	if g == nil || g.cfg.Store == nil {
		return nil
	}
	rules := []string{}
	for _, collection := range []string{"ssh_gateways", "system_settings"} {
		items, err := g.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			continue
		}
		for _, item := range items {
			if !platformItemEnabled(item) {
				continue
			}
			if collection == "system_settings" && !strings.EqualFold(strings.TrimSpace(item.Type), "proxy") {
				continue
			}
			rules = append(rules, forwardAllowlistFromItem(item)...)
		}
	}
	return rules
}

func forwardAllowlistFromItem(item model.PlatformItem) []string {
	keys := []string{
		"forward_whitelist",
		"forward_allowlist",
		"port_forward_whitelist",
		"port_forward_allowlist",
		"forward_targets",
		"allowed_forwards",
		"ssh_forward_whitelist",
		"ssh_forward_allowlist",
		"tcp_forward_whitelist",
		"tcp_forward_allowlist",
	}
	rules := []string{}
	for _, key := range keys {
		for _, value := range metadataStrings(item.Metadata[key]) {
			for _, part := range splitCriteria(value) {
				if part = strings.TrimSpace(part); part != "" {
					rules = append(rules, part)
				}
			}
		}
	}
	return rules
}

func forwardHostMatchesAsset(host string, asset model.PlatformItem) bool {
	host = normalizeForwardHost(host)
	if host == "" {
		return false
	}
	candidates := []string{asset.Host, asset.ID, asset.Name, asset.Username, asset.TargetID}
	candidates = append(candidates, metadataStrings(asset.Metadata["alias"])...)
	candidates = append(candidates, metadataStrings(asset.Metadata["aliases"])...)
	for _, candidate := range candidates {
		for _, part := range splitCriteria(candidate) {
			if strings.EqualFold(host, normalizeForwardHost(part)) {
				return true
			}
		}
	}
	return false
}

func forwardRuleMatches(rule, host string, port int) bool {
	ruleHost, rulePort := parseForwardRule(rule)
	if ruleHost == "" && rulePort == "" {
		return false
	}
	if ruleHost == "" {
		ruleHost = "*"
	}
	if rulePort == "" {
		rulePort = "*"
	}
	hostMatches := ruleHost == "*" || strings.EqualFold(normalizeForwardHost(ruleHost), normalizeForwardHost(host))
	portMatches := rulePort == "*" || rulePort == strconv.Itoa(port)
	return hostMatches && portMatches
}

func parseForwardRule(rule string) (string, string) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return "", ""
	}
	if rule == "*" || rule == "*:*" {
		return "*", "*"
	}
	if host, port, err := net.SplitHostPort(rule); err == nil {
		return strings.TrimSpace(host), strings.TrimSpace(port)
	}
	if strings.HasPrefix(rule, "*:") {
		return "*", strings.TrimSpace(strings.TrimPrefix(rule, "*:"))
	}
	if index := strings.LastIndex(rule, ":"); index > 0 && !strings.Contains(rule[:index], ":") {
		return strings.TrimSpace(rule[:index]), strings.TrimSpace(rule[index+1:])
	}
	return rule, "*"
}

func normalizeForwardHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

func (g *Gateway) auditForward(conn *ssh.ServerConn, user gatewayUser, host string, port int, status, detail string) error {
	if g == nil || g.cfg.Store == nil {
		return errors.New("forwarding audit store is unavailable")
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	if strings.TrimSpace(detail) != "" {
		detail = target + " " + detail
	} else {
		detail = target
	}
	_, err := g.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "ssh_gateway.forward." + strings.TrimSpace(status),
		Type:        "ssh_gateway",
		Status:      strings.TrimSpace(status),
		Protocol:    model.ProtocolSSH,
		OwnerID:     user.UserID,
		TargetID:    target,
		Description: detail,
		Metadata: map[string]any{
			"client_ip": remoteIP(conn.RemoteAddr()),
			"host":      host,
			"port":      port,
		},
	})
	return err
}

func (g *Gateway) auditForwardPersistFailure(conn *ssh.ServerConn, user gatewayUser, host string, port int, status string, err error) {
	if g == nil || g.cfg.Store == nil || err == nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	_ = g.cfg.Store.Audit(model.AuditLog{
		UserID:   user.UserID,
		Action:   "ssh_gateway.forward.log.persist_failed",
		TargetID: target,
		Protocol: model.ProtocolSSH,
		Detail:   "persist " + strings.TrimSpace(status) + " forwarding audit: " + err.Error(),
		ClientIP: remoteIP(conn.RemoteAddr()),
	})
}

func proxyTCPChannel(channel ssh.Channel, upstream net.Conn, onClose func()) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = channel.Close()
			_ = upstream.Close()
			if onClose != nil {
				onClose()
			}
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, channel)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, upstream)
		closeBoth()
	}()
	wg.Wait()
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
	client, err := dial(server, legacyCredential, secret, g.cfg.KnownHostsPath, nil)
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
	if _, err := g.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
		item.Status = model.SessionActive
	}); err != nil {
		_ = targetSession.Close()
		_ = client.Close()
		return nil, fmt.Errorf("mark session active: %w", err)
	}
	var once sync.Once
	closeAll := func(reason string) {
		once.Do(func() {
			_ = targetSession.Close()
			_ = client.Close()
			now := time.Now().UTC()
			if _, err := g.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
				item.Status = model.SessionClosed
				item.EndedAt = &now
				if reason != "" {
					item.Error = reason
				}
			}); err != nil {
				_ = g.cfg.Store.Audit(model.AuditLog{
					UserID:   session.UserID,
					Action:   "ssh_gateway.session.close_state.persist_failed",
					TargetID: session.ServerID,
					Protocol: model.ProtocolSSH,
					Detail:   "session " + session.ID + ": " + err.Error(),
					ClientIP: session.ClientIP,
				})
			}
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
			if len(filtered) > 0 {
				if _, writeErr := writer.Write(filtered); writeErr != nil {
					closeAll(writeErr.Error())
					return
				}
			}
			fatal := false
			for _, event := range events {
				if event.Blocked {
					_, _ = channel.Write([]byte(event.Notice))
				}
				if event.Fatal {
					fatal = true
				}
			}
			if fatal {
				closeAll("command audit unavailable")
				return
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
		addGatewayMetadataKeys(userKeys, user.Metadata, "department_id", "department_ids", "departmentId", "department", "departments", "dept_id", "dept_ids", "dept", "depts", "group_id", "group_ids", "groupId")
		expandGatewayRelatedKeys(platform["departments"], userKeys)
		break
	}
	for _, authorization := range platform["authorized_assets"] {
		if !gatewayAuthorizationActive(authorization) || !gatewayAuthorizationSubjectMatches(authorization, userKeys) {
			continue
		}
		if gatewayAuthorizationTargetMatches(platform, authorization, asset) {
			return true
		}
	}
	return false
}

func gatewayAuthorizationActive(authorization model.PlatformItem) bool {
	if !platformItemEnabled(authorization) {
		return false
	}
	for _, key := range []string{"expires_at", "expire_at", "expiresAt", "expired_at", "valid_until", "not_after"} {
		expiresAt, ok := gatewayMetadataTime(authorization.Metadata[key])
		if ok && !expiresAt.IsZero() && !time.Now().UTC().Before(expiresAt) {
			return false
		}
	}
	return true
}

func gatewayAuthorizationSubjectMatches(authorization model.PlatformItem, userKeys map[string]bool) bool {
	keys := map[string]bool{}
	addGatewayAuthKeys(keys, authorization.OwnerID, authorization.Username, authorization.ParentID, authorization.Group)
	addGatewayMetadataKeys(keys, authorization.Metadata, "subject_id", "subject_ids", "subjectId", "user_id", "user_ids", "userId", "username", "usernames", "account", "accounts", "owner_id", "owner_ids", "ownerId", "department_id", "department_ids", "departmentId", "department", "departments", "dept_id", "dept_ids", "dept", "depts")
	return gatewayKeysOverlap(userKeys, keys)
}

func gatewayAuthorizationTargetMatches(platform map[string][]model.PlatformItem, authorization, asset model.PlatformItem) bool {
	targetKeys := map[string]bool{}
	addGatewayAuthKeys(targetKeys, authorization.TargetID, authorization.ParentID, authorization.Group)
	addGatewayMetadataKeys(targetKeys, authorization.Metadata, "target_id", "target_ids", "targetId", "asset_id", "asset_ids", "assetId", "resource_id", "resource_ids", "resourceId", "asset_group_id", "asset_group_ids", "assetGroupId", "target_group_id", "target_group_ids", "targetGroupId", "group_id", "group_ids", "groupId", "group", "groups")
	if targetKeys["*"] {
		return true
	}
	assetKeys := map[string]bool{}
	addGatewayAuthKeys(assetKeys, asset.ID, asset.Name, asset.TargetID, asset.ParentID, asset.Group)
	addGatewayMetadataKeys(assetKeys, asset.Metadata, "asset_id", "asset_ids", "assetId", "asset_group_id", "asset_group_ids", "assetGroupId", "group_id", "group_ids", "groupId", "parent_id", "parent_ids", "parentId")
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
			changed = addGatewayMetadataKeys(keys, item.Metadata, "parent_id", "parent_ids", "parentId", "group_id", "group_ids", "groupId") || changed
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

func loadGatewaySigner(cfg GatewayConfig) (ssh.Signer, error) {
	if strings.TrimSpace(cfg.HostKeyPEM) != "" {
		signer, err := ssh.ParsePrivateKey([]byte(cfg.HostKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("parse configured ssh gateway host key: %w", err)
		}
		return signer, nil
	}
	return loadGatewayHostSigner(filepath.Join(cfg.DataDir, "ssh_gateway_host_key"))
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

func gatewayDisablePasswordAuth(item model.PlatformItem) (bool, bool) {
	for _, key := range []string{"disable_password_auth", "disablePasswordAuth", "password_auth_disabled", "disable_password_login"} {
		if value, ok := gatewayMetadataBool(item.Metadata[key]); ok {
			return value, true
		}
	}
	return false, false
}

func gatewayMetadataBool(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case int:
		return typed != 0, true
	case int64:
		return typed != 0, true
	case float64:
		return typed != 0, true
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "true", "1", "yes", "enabled", "on":
			return true, true
		case "false", "0", "no", "disabled", "off":
			return false, true
		default:
			return false, false
		}
	default:
		values := metadataStrings(value)
		for _, item := range values {
			if parsed, ok := gatewayMetadataBool(item); ok {
				return parsed, true
			}
		}
		return false, false
	}
}

func gatewayMetadataTime(value any) (time.Time, bool) {
	switch typed := value.(type) {
	case time.Time:
		return typed.UTC(), true
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return time.Time{}, false
		}
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05"} {
			parsed, err := time.Parse(layout, text)
			if err == nil {
				return parsed.UTC(), true
			}
		}
	case float64:
		return time.Unix(int64(typed), 0).UTC(), true
	case int:
		return time.Unix(int64(typed), 0).UTC(), true
	case int64:
		return time.Unix(typed, 0).UTC(), true
	}
	return time.Time{}, false
}

func userFromPermissions(permissions *ssh.Permissions) gatewayUser {
	if permissions == nil {
		return gatewayUser{}
	}
	isAdmin, _ := strconv.ParseBool(permissions.Extensions["is_admin"])
	return gatewayUser{
		UserID:      permissions.Extensions["user_id"],
		Username:    permissions.Extensions["username"],
		Role:        permissions.Extensions["role"],
		IsAdmin:     isAdmin,
		DirectAsset: strings.TrimSpace(permissions.Extensions["direct_asset"]),
	}
}

func splitGatewayUsername(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if username, asset, ok := splitGatewayUsernameAt(raw, "#"); ok {
		return username, asset
	}
	if username, asset, ok := splitGatewayUsernameAt(raw, ":"); ok {
		return username, asset
	}
	return raw, ""
}

func splitGatewayUsernameAt(raw, separator string) (string, string, bool) {
	index := strings.LastIndex(raw, separator)
	if index <= 0 || index >= len(raw)-len(separator) {
		return "", "", false
	}
	username := strings.TrimSpace(raw[:index])
	asset := strings.TrimSpace(raw[index+len(separator):])
	if username == "" || asset == "" {
		return "", "", false
	}
	return username, asset, true
}

func gatewayRoleIsAdmin(role string) bool {
	return roles.IsAdmin(role)
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
