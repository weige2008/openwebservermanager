package app

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

type sequentialProxyTestRuntime interface {
	Address() string
	Routes() []proxyRouteStatus
	LastError() string
	Close() error
}

type sequentialProxyTestSpec struct {
	name         string
	statusKey    string
	enabledKey   string
	listenKey    string
	allowlistKey string
	auditAction  string
	newRuntime   func(context.Context, *Config) sequentialProxyTestRuntime
}

type sequentialProxyTestResponse struct {
	Status map[string]struct {
		State         string             `json:"state"`
		ListenAddress string             `json:"listen_address"`
		LiveAddress   string             `json:"live_address"`
		LastError     string             `json:"last_error"`
		Routes        []proxyRouteStatus `json:"routes"`
	} `json:"status"`
}

func TestRDPProxyRuntimeMapsSequentialTargets(t *testing.T) {
	testSequentialProxyRuntime(t, sequentialProxyTestSpec{
		name:         "rdp",
		statusKey:    "rdp_proxy",
		enabledKey:   "rdp_enabled",
		listenKey:    "rdp_listen_address",
		allowlistKey: "rdp_forward_allowlist",
		auditAction:  "rdp_proxy.connect",
		newRuntime: func(ctx context.Context, cfg *Config) sequentialProxyTestRuntime {
			runtime := NewRDPProxyManager(ctx, cfg.Store, slog.Default())
			cfg.RDPProxy = runtime
			return runtime
		},
	})
}

func TestDatabaseProxyRuntimeMapsSequentialTargets(t *testing.T) {
	testSequentialProxyRuntime(t, sequentialProxyTestSpec{
		name:         "database",
		statusKey:    "database_proxy",
		enabledKey:   "database_enabled",
		listenKey:    "database_listen_address",
		allowlistKey: "database_forward_allowlist",
		auditAction:  "database_proxy.connect",
		newRuntime: func(ctx context.Context, cfg *Config) sequentialProxyTestRuntime {
			runtime := NewDatabaseProxyManager(ctx, cfg.Store, slog.Default())
			cfg.DatabaseProxy = runtime
			return runtime
		},
	})
}

func testSequentialProxyRuntime(t *testing.T, spec sequentialProxyTestSpec) {
	t.Helper()
	firstTarget, firstReceived, closeFirstTarget := startEchoTCPServer(t)
	defer closeFirstTarget()
	secondTarget, secondReceived, closeSecondTarget := startEchoTCPServer(t)
	defer closeSecondTarget()

	reserved, baseAddress := reserveLocalTCPRange(t, 2)
	closeTCPListeners(t, reserved)

	var runtime sequentialProxyTestRuntime
	handler, cookie := newTestServer(t, func(cfg *Config) {
		ctx, cancel := context.WithCancel(context.Background())
		runtime = spec.newRuntime(ctx, cfg)
		t.Cleanup(func() {
			_ = runtime.Close()
			cancel()
		})
	})

	response := saveSequentialProxySettings(t, handler, cookie, spec, true, baseAddress, []string{firstTarget, secondTarget})
	status := response.Status[spec.statusKey]
	wantRoutes, err := buildSequentialProxyRoutes(baseAddress, []string{firstTarget, secondTarget})
	if err != nil {
		t.Fatalf("build expected %s routes: %v", spec.name, err)
	}
	assertSequentialProxyStatus(t, spec.name, status.State, status.Routes, "running", wantRoutes)
	assertProxyEcho(t, status.Routes[0].ListenAddress, spec.name+" first\n", firstReceived)
	assertProxyEcho(t, status.Routes[1].ListenAddress, spec.name+" second\n", secondReceived)
	waitForCondition(t, 2*time.Second, func() bool {
		rec := assertStatus(t, handler, http.MethodGet, "/api/admin/audit/operation-logs", nil, cookie, http.StatusOK)
		body := rec.Body.String()
		return strings.Contains(body, spec.auditAction) && strings.Contains(body, firstTarget) && strings.Contains(body, secondTarget)
	})

	response = saveSequentialProxySettings(t, handler, cookie, spec, true, baseAddress, []string{secondTarget, firstTarget})
	status = response.Status[spec.statusKey]
	wantRoutes, err = buildSequentialProxyRoutes(baseAddress, []string{secondTarget, firstTarget})
	if err != nil {
		t.Fatalf("build reloaded %s routes: %v", spec.name, err)
	}
	assertSequentialProxyStatus(t, spec.name, status.State, status.Routes, "running", wantRoutes)
	assertProxyEcho(t, status.Routes[0].ListenAddress, spec.name+" reloaded first\n", secondReceived)
	assertProxyEcho(t, status.Routes[1].ListenAddress, spec.name+" reloaded second\n", firstReceived)

	previousRoutes := runtime.Routes()
	blockedRange, blockedBaseAddress := reserveLocalTCPRange(t, 2)
	if err := blockedRange[0].Close(); err != nil {
		t.Fatalf("release first %s blocked-range listener: %v", spec.name, err)
	}
	defer func() { _ = blockedRange[1].Close() }()
	response = saveSequentialProxySettings(t, handler, cookie, spec, true, blockedBaseAddress, []string{firstTarget, secondTarget})
	status = response.Status[spec.statusKey]
	if status.State != "port_unavailable" || status.LastError == "" {
		t.Fatalf("%s partial-start failure state=%q error=%q", spec.name, status.State, status.LastError)
	}
	assertProxyRoutesEqual(t, spec.name+" restored routes", status.Routes, previousRoutes)
	assertProxyRoutesEqual(t, spec.name+" runtime routes", runtime.Routes(), previousRoutes)
	assertProxyEcho(t, previousRoutes[0].ListenAddress, spec.name+" restored first\n", secondReceived)
	assertProxyEcho(t, previousRoutes[1].ListenAddress, spec.name+" restored second\n", firstReceived)

	response = saveSequentialProxySettings(t, handler, cookie, spec, false, blockedBaseAddress, []string{firstTarget, secondTarget})
	status = response.Status[spec.statusKey]
	if status.State != "disabled" || len(runtime.Routes()) != 0 {
		t.Fatalf("%s disable state=%q routes=%#v", spec.name, status.State, runtime.Routes())
	}
	for _, route := range previousRoutes {
		if conn, err := net.DialTimeout("tcp", route.ListenAddress, 100*time.Millisecond); err == nil {
			_ = conn.Close()
			t.Fatalf("%s listener %s remained open after disable", spec.name, route.ListenAddress)
		}
	}

	response = saveSequentialProxySettings(t, handler, cookie, spec, true, "127.0.0.1:65535", []string{firstTarget, secondTarget})
	status = response.Status[spec.statusKey]
	if status.State != "invalid_config" || !strings.Contains(status.LastError, "exceeds port 65535") {
		t.Fatalf("%s overflow state=%q error=%q", spec.name, status.State, status.LastError)
	}
}

func saveSequentialProxySettings(t *testing.T, handler http.Handler, cookie *http.Cookie, spec sequentialProxyTestSpec, enabled bool, listenAddress string, targets []string) sequentialProxyTestResponse {
	t.Helper()
	rec := assertStatus(t, handler, http.MethodPost, "/api/admin/proxy-services", map[string]any{
		spec.enabledKey:   enabled,
		spec.listenKey:    listenAddress,
		spec.allowlistKey: targets,
	}, cookie, http.StatusOK)
	var response sequentialProxyTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode %s proxy response: %v: %s", spec.name, err, rec.Body.String())
	}
	return response
}

func assertSequentialProxyStatus(t *testing.T, name, state string, got []proxyRouteStatus, wantState string, want []proxyRouteStatus) {
	t.Helper()
	if state != wantState {
		t.Fatalf("%s state=%q, want %q", name, state, wantState)
	}
	assertProxyRoutesEqual(t, name+" routes", got, want)
}

func assertProxyRoutesEqual(t *testing.T, name string, got, want []proxyRouteStatus) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s count=%d, want %d: %#v", name, len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("%s[%d]=%#v, want %#v", name, index, got[index], want[index])
		}
	}
}

func assertProxyEcho(t *testing.T, address, payload string, received <-chan string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy route %s: %v", address, err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		_ = conn.Close()
		t.Fatalf("write proxy route %s: %v", address, err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if closeErr := conn.Close(); closeErr != nil {
		t.Fatalf("close proxy route %s: %v", address, closeErr)
	}
	if err != nil || line != "echo:"+payload {
		t.Fatalf("proxy route %s response=%q err=%v", address, line, err)
	}
	select {
	case got := <-received:
		if got != payload {
			t.Fatalf("proxy route %s upstream payload=%q, want %q", address, got, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("proxy route %s did not reach upstream", address)
	}
}

func reserveLocalTCPRange(t *testing.T, count int) ([]net.Listener, string) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		seed, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("find local tcp range: %v", err)
		}
		port := seed.Addr().(*net.TCPAddr).Port
		_ = seed.Close()
		if port+count-1 > 65535 {
			continue
		}
		listeners := make([]net.Listener, 0, count)
		for offset := 0; offset < count; offset++ {
			listener, listenErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port+offset)))
			if listenErr != nil {
				for _, item := range listeners {
					_ = item.Close()
				}
				listeners = nil
				break
			}
			listeners = append(listeners, listener)
		}
		if len(listeners) == count {
			return listeners, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		}
	}
	t.Fatalf("could not reserve %d consecutive local tcp ports", count)
	return nil, fmt.Sprintf("127.0.0.1:%d", 0)
}

func closeTCPListeners(t *testing.T, listeners []net.Listener) {
	t.Helper()
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatalf("release reserved tcp listener: %v", err)
		}
	}
}
