package guac

import (
	"path/filepath"
	"strings"
	"testing"

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/security"
	"openwebservermanager/internal/store"
)

func TestDesktopPolicyArguments(t *testing.T) {
	tunnel := Tunnel{DataDir: t.TempDir()}
	cfg := DesktopConfig{
		Protocol:         model.ProtocolRDP,
		Session:          model.ConnectionSession{ID: "sess_policy"},
		Host:             "127.0.0.1",
		Port:             3390,
		Username:         "Administrator",
		Password:         "secret",
		Width:            1600,
		Height:           1000,
		DPI:              120,
		ColorDepth:       16,
		IgnoreCert:       false,
		EnableDrive:      false,
		ClipboardEnabled: false,
		ReadOnly:         true,
		ResizeMethod:     "reconnect",
	}
	assertArg := func(name, want string) {
		t.Helper()
		if got := tunnel.argValue(name, cfg); got != want {
			t.Fatalf("arg %s = %q, want %q", name, got, want)
		}
	}
	assertArg("port", "3390")
	assertArg("color-depth", "16")
	assertArg("resize-method", "reconnect")
	assertArg("enable-drive", "false")
	assertArg("read-only", "true")
	assertArg("disable-copy", "true")
	assertArg("disable-paste", "true")
	assertArg("ignore-cert", "false")
	assertArg("width", "1600")
	assertArg("height", "1000")
	assertArg("dpi", "120")
}

func TestDesktopInstructionFilterBlocksDisabledClipboardAndFileTransfer(t *testing.T) {
	filter := newDesktopInstructionFilter(Tunnel{}, DesktopConfig{
		Protocol:         model.ProtocolRDP,
		Session:          model.ConnectionSession{ID: "sess_filter"},
		ClipboardEnabled: false,
		EnableDrive:      false,
	})
	payload := append([]byte{}, Encode("clipboard", "7", "text/plain")...)
	payload = append(payload, Encode("blob", "7", "secret")...)
	payload = append(payload, Encode("end", "7")...)
	payload = append(payload, Encode("file", "8", "text/plain", "secret.txt")...)
	payload = append(payload, Encode("blob", "8", "payload")...)
	payload = append(payload, Encode("end", "8")...)
	payload = append(payload, Encode("key", "1", "65")...)

	filtered, err := filter.filterPayload(directionBrowser, payload, nil)
	if err != nil {
		t.Fatalf("filter payload: %v", err)
	}
	if string(filtered) != string(Encode("key", "1", "65")) {
		t.Fatalf("filtered payload = %q", string(filtered))
	}
}

func TestDesktopInstructionFilterAuditsFileTransfers(t *testing.T) {
	key := make([]byte, 32)
	cipher, err := security.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"), cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	filter := newDesktopInstructionFilter(Tunnel{Store: st}, DesktopConfig{
		Protocol:         model.ProtocolRDP,
		Session:          model.ConnectionSession{ID: "sess_audit", UserID: "user_1", ServerID: "asset_1"},
		ClipboardEnabled: true,
		EnableDrive:      true,
	})
	payload := append([]byte{}, Encode("file", "9", "text/plain", "report.txt")...)
	payload = append(payload, Encode("blob", "9", "payload")...)
	payload = append(payload, Encode("end", "9")...)
	if _, err := filter.filterPayload(directionBrowser, payload, nil); err != nil {
		t.Fatalf("filter payload: %v", err)
	}

	items, err := st.ListPlatformItems("file_logs")
	if err != nil {
		t.Fatalf("list file logs: %v", err)
	}
	body := ""
	for _, item := range items {
		body += item.Name + ":" + item.Type + ":" + item.Status + ":" + item.Description + "\n"
	}
	for _, expected := range []string{"report.txt:upload:started", "report.txt:upload:completed"} {
		if !strings.Contains(body, expected) {
			t.Fatalf("file transfer audit missing %q in %s", expected, body)
		}
	}
}

func TestDesktopInstructionFilterEnforcesFilePermissionCallback(t *testing.T) {
	checked := []string{}
	filter := newDesktopInstructionFilter(Tunnel{}, DesktopConfig{
		Protocol:    model.ProtocolRDP,
		Session:     model.ConnectionSession{ID: "sess_file_policy"},
		EnableDrive: true,
		FilePermission: func(operation, path string) bool {
			checked = append(checked, operation+":"+path)
			return operation == "download"
		},
	})
	upload := append([]byte{}, Encode("file", "12", "text/plain", "blocked.txt")...)
	upload = append(upload, Encode("blob", "12", "payload")...)
	upload = append(upload, Encode("end", "12")...)
	filteredUpload, err := filter.filterPayload(directionBrowser, upload, nil)
	if err != nil {
		t.Fatalf("filter denied upload: %v", err)
	}
	if len(filteredUpload) != 0 {
		t.Fatalf("denied upload leaked upstream: %q", string(filteredUpload))
	}
	download := append([]byte{}, Encode("file", "13", "text/plain", "allowed.txt")...)
	download = append(download, Encode("blob", "13", "payload")...)
	download = append(download, Encode("end", "13")...)
	filteredDownload, err := filter.filterPayload(directionGuacd, download, nil)
	if err != nil {
		t.Fatalf("filter allowed download: %v", err)
	}
	if string(filteredDownload) != string(download) {
		t.Fatalf("allowed download was filtered: %q", string(filteredDownload))
	}
	if strings.Join(checked, ",") != "upload:blocked.txt,download:allowed.txt" {
		t.Fatalf("file permission checks = %v", checked)
	}
}

func TestDesktopInstructionFilterAuditsClipboardTransfers(t *testing.T) {
	key := make([]byte, 32)
	cipher, err := security.NewCipher(key)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"), cipher)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	filter := newDesktopInstructionFilter(Tunnel{Store: st}, DesktopConfig{
		Protocol:         model.ProtocolRDP,
		Session:          model.ConnectionSession{ID: "sess_clipboard", UserID: "user_1", ServerID: "asset_1"},
		ClipboardEnabled: true,
		EnableDrive:      true,
	})
	for _, tc := range []struct {
		direction guacDirection
		streamID  string
	}{
		{direction: directionBrowser, streamID: "10"},
		{direction: directionGuacd, streamID: "11"},
	} {
		payload := append([]byte{}, Encode("clipboard", tc.streamID, "text/plain")...)
		payload = append(payload, Encode("blob", tc.streamID, "payload")...)
		payload = append(payload, Encode("end", tc.streamID)...)
		if _, err := filter.filterPayload(tc.direction, payload, nil); err != nil {
			t.Fatalf("filter %s clipboard payload: %v", tc.direction, err)
		}
	}

	items, err := st.ListPlatformItems("operation_logs")
	if err != nil {
		t.Fatalf("list operation logs: %v", err)
	}
	body := ""
	for _, item := range items {
		if item.Type != "clipboard" {
			continue
		}
		direction, _ := item.Metadata["direction"].(string)
		sessionID, _ := item.Metadata["session_id"].(string)
		body += item.Name + ":" + item.Status + ":" + direction + ":" + sessionID + "\n"
	}
	for _, expected := range []string{
		"desktop.clipboard.started:started:browser:sess_clipboard",
		"desktop.clipboard.completed:completed:browser:sess_clipboard",
		"desktop.clipboard.started:started:guacd:sess_clipboard",
		"desktop.clipboard.completed:completed:guacd:sess_clipboard",
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("clipboard audit missing %q in %s", expected, body)
		}
	}
}
