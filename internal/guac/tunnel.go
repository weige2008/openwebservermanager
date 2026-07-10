package guac

import (
	"bufio"
	"bytes"
	"context"
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

	"openwebservermanager/internal/model"
	"openwebservermanager/internal/store"
	"openwebservermanager/internal/ws"
)

type Tunnel struct {
	Manager *Manager
	Store   *store.Store
	Logger  *slog.Logger
	DataDir string
}

type RDPConfig struct {
	Session    model.ConnectionSession
	Server     model.Server
	Credential model.Credential
	Secret     store.CredentialSecret
	Width      int
	Height     int
	DPI        int
}

type DesktopConfig struct {
	Protocol         model.Protocol
	Session          model.ConnectionSession
	Host             string
	Port             int
	Username         string
	Password         string
	Domain           string
	Width            int
	Height           int
	DPI              int
	ColorDepth       int
	IgnoreCert       bool
	EnableDrive      bool
	ClipboardEnabled bool
	ReadOnly         bool
	ResizeMethod     string
	FilePermission   func(operation, path string) bool
}

type guacDirection string

const (
	directionBrowser guacDirection = "browser"
	directionGuacd   guacDirection = "guacd"
)

type desktopStream struct {
	Kind      string
	Operation string
	Name      string
	MimeType  string
	Blocked   bool
}

type desktopInstructionFilter struct {
	tunnel  Tunnel
	cfg     DesktopConfig
	mu      sync.Mutex
	streams map[string]desktopStream
}

func (t Tunnel) Run(ctx context.Context, browser *ws.Conn, cfg RDPConfig) {
	port := cfg.Server.RDPPort
	if port == 0 {
		port = 3389
	}
	t.RunDesktop(ctx, browser, DesktopConfig{
		Protocol:         model.ProtocolRDP,
		Session:          cfg.Session,
		Host:             cfg.Server.Host,
		Port:             port,
		Username:         cfg.Credential.Username,
		Password:         cfg.Secret.Password,
		Domain:           cfg.Credential.Domain,
		Width:            cfg.Width,
		Height:           cfg.Height,
		DPI:              cfg.DPI,
		ColorDepth:       24,
		IgnoreCert:       true,
		EnableDrive:      true,
		ClipboardEnabled: true,
		ResizeMethod:     "display-update",
	})
}

func (t Tunnel) RunDesktop(ctx context.Context, browser *ws.Conn, cfg DesktopConfig) {
	defer browser.Close()

	if cfg.Width <= 0 {
		cfg.Width = 1440
	}
	if cfg.Height <= 0 {
		cfg.Height = 900
	}
	if cfg.DPI <= 0 {
		cfg.DPI = 96
	}
	if cfg.ResizeMethod == "" {
		cfg.ResizeMethod = "display-update"
	}
	trace := t.newTrace(cfg.Session.ID)

	guacd, err := t.Manager.Dial(ctx)
	if err != nil {
		t.fail(cfg.Session.ID, fmt.Errorf("connect guacd: %w", err))
		return
	}
	defer guacd.Close()

	reader := bufio.NewReader(guacd)
	if err := t.handshake(guacd, reader, cfg); err != nil {
		t.fail(cfg.Session.ID, err)
		return
	}
	if err := browser.SendText(Encode("", cfg.Session.ID)); err != nil {
		t.fail(cfg.Session.ID, fmt.Errorf("open browser tunnel: %w", err))
		return
	}

	_, _ = t.Store.UpdateSession(cfg.Session.ID, func(item *model.ConnectionSession) {
		item.Status = model.SessionActive
		item.Width = cfg.Width
		item.Height = cfg.Height
	})

	var once sync.Once
	closeSession := func(reason string) {
		once.Do(func() {
			now := time.Now().UTC()
			_, _ = t.Store.UpdateSession(cfg.Session.ID, func(item *model.ConnectionSession) {
				if item.Status == model.SessionClosed && item.EndedAt != nil {
					return
				}
				item.Status = model.SessionClosed
				item.EndedAt = &now
				if cfg.Session.RecordingPath != "" {
					item.RecordingSize = directorySize(cfg.Session.RecordingPath)
				}
				if reason != "" {
					item.Error = reason
				}
			})
		})
	}

	filter := newDesktopInstructionFilter(t, cfg)

	go func() {
		for {
			instruction, raw, err := ReadInstruction(reader)
			if err != nil {
				if err != io.EOF {
					closeSession(err.Error())
				} else {
					closeSession("")
				}
				return
			}
			trace("guacd", instruction, len(raw))
			if !filter.allowInstruction(directionGuacd, instruction) {
				continue
			}
			if err := browser.SendText(raw); err != nil {
				closeSession(err.Error())
				return
			}
		}
	}()

	for {
		op, payload, err := browser.ReadFrame()
		if err != nil {
			closeSession("")
			return
		}
		switch op {
		case 1, 2:
			payload, err := filter.filterPayload(directionBrowser, payload, func(instruction Instruction, raw []byte) {
				trace("browser", instruction, len(raw))
			})
			if err != nil {
				closeSession(err.Error())
				return
			}
			if len(payload) == 0 {
				continue
			}
			if _, err := guacd.Write(payload); err != nil {
				closeSession(err.Error())
				return
			}
			_, _ = t.Store.UpdateSession(cfg.Session.ID, func(item *model.ConnectionSession) {})
		case 8:
			closeSession("")
			return
		case 9:
			_ = browser.SendPong(payload)
		}
	}
}

func newDesktopInstructionFilter(tunnel Tunnel, cfg DesktopConfig) *desktopInstructionFilter {
	return &desktopInstructionFilter{
		tunnel:  tunnel,
		cfg:     cfg,
		streams: map[string]desktopStream{},
	}
}

func (f *desktopInstructionFilter) filterPayload(direction guacDirection, payload []byte, trace func(Instruction, []byte)) ([]byte, error) {
	reader := bufio.NewReader(bytes.NewReader(payload))
	var out bytes.Buffer
	for {
		instruction, raw, err := ReadInstruction(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if trace != nil {
			trace(instruction, raw)
		}
		// Guacamole WebSocketTunnel uses the empty opcode for tunnel keepalive
		// messages. guacd only understands protocol instructions, so these stay
		// inside the browser-to-Go tunnel and are not forwarded upstream.
		if instruction.Opcode == "" {
			continue
		}
		if !f.allowInstruction(direction, instruction) {
			continue
		}
		out.Write(raw)
	}
	return out.Bytes(), nil
}

func (f *desktopInstructionFilter) allowInstruction(direction guacDirection, instruction Instruction) bool {
	streamID := firstArg(instruction)
	streamKey := string(direction) + ":" + streamID
	switch instruction.Opcode {
	case "":
		return false
	case "clipboard":
		stream := desktopStream{Kind: "clipboard", Operation: "clipboard", MimeType: argAt(instruction, 1), Blocked: !f.cfg.ClipboardEnabled}
		f.setStream(streamKey, stream)
		f.auditStreamEvent(direction, stream, "started")
		return !stream.Blocked
	case "file":
		operation := "download"
		if direction == directionBrowser {
			operation = "upload"
		}
		name := argAt(instruction, 2)
		blocked := !f.cfg.EnableDrive
		if !blocked && f.cfg.FilePermission != nil {
			blocked = !f.cfg.FilePermission(operation, name)
		}
		stream := desktopStream{Kind: "file", Operation: operation, MimeType: argAt(instruction, 1), Name: name, Blocked: blocked}
		f.setStream(streamKey, stream)
		f.auditStreamEvent(direction, stream, "started")
		return !stream.Blocked
	case "blob", "ack":
		if stream, ok := f.stream(streamKey); ok && stream.Blocked {
			return false
		}
	case "end":
		if stream, ok := f.deleteStream(streamKey); ok {
			if stream.Blocked {
				return false
			}
			f.auditStreamEvent(direction, stream, "completed")
		}
	}
	return true
}

func (f *desktopInstructionFilter) setStream(key string, stream desktopStream) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.streams[key] = stream
}

func (f *desktopInstructionFilter) stream(key string) (desktopStream, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stream, ok := f.streams[key]
	return stream, ok
}

func (f *desktopInstructionFilter) deleteStream(key string) (desktopStream, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stream, ok := f.streams[key]
	if ok {
		delete(f.streams, key)
	}
	return stream, ok
}

func (f *desktopInstructionFilter) auditStreamEvent(direction guacDirection, stream desktopStream, status string) {
	if f.tunnel.Store == nil {
		return
	}
	if stream.Blocked {
		status = "blocked"
	}
	switch stream.Kind {
	case "file":
		name := stream.Name
		if name == "" {
			name = f.cfg.Session.ID
		}
		_, _ = f.tunnel.Store.CreatePlatformItem("file_logs", model.PlatformItemRequest{
			Name:        name,
			Type:        stream.Operation,
			Status:      status,
			Protocol:    f.cfg.Protocol,
			OwnerID:     f.cfg.Session.UserID,
			TargetID:    f.cfg.Session.ServerID,
			Description: "desktop file transfer " + status,
			Metadata: map[string]any{
				"session_id": f.cfg.Session.ID,
				"direction":  string(direction),
				"operation":  stream.Operation,
				"mime_type":  stream.MimeType,
				"blocked":    stream.Blocked,
			},
		})
	case "clipboard":
		_, _ = f.tunnel.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
			Name:        "desktop.clipboard." + status,
			Type:        "clipboard",
			Status:      status,
			Protocol:    f.cfg.Protocol,
			OwnerID:     f.cfg.Session.UserID,
			TargetID:    f.cfg.Session.ServerID,
			Description: "desktop clipboard " + status,
			Metadata: map[string]any{
				"session_id": f.cfg.Session.ID,
				"direction":  string(direction),
				"mime_type":  stream.MimeType,
				"blocked":    stream.Blocked,
			},
		})
	}
}

func firstArg(instruction Instruction) string {
	return argAt(instruction, 0)
}

func argAt(instruction Instruction, index int) string {
	if index < 0 || index >= len(instruction.Args) {
		return ""
	}
	return instruction.Args[index]
}

func (t Tunnel) newTrace(sessionID string) func(string, Instruction, int) {
	if envAny("OPENWEBSERVERMANAGER_GUAC_TRACE", "SERVERMANAGER_GUAC_TRACE") != "1" || t.Logger == nil {
		return func(string, Instruction, int) {}
	}
	var mu sync.Mutex
	counts := map[string]int{}
	t.Logger.Info("guacamole trace enabled", "session", sessionID)
	return func(direction string, instruction Instruction, rawLen int) {
		key := direction + ":" + instruction.Opcode
		mu.Lock()
		counts[key]++
		count := counts[key]
		mu.Unlock()
		if count > 20 {
			return
		}
		t.Logger.Info(
			"guacamole instruction",
			"session", sessionID,
			"direction", direction,
			"opcode", instruction.Opcode,
			"count", count,
			"args", len(instruction.Args),
			"sample", summarizeTraceArgs(instruction),
			"bytes", rawLen,
		)
	}
}

func summarizeTraceArgs(instruction Instruction) []string {
	switch instruction.Opcode {
	case "blob":
		if len(instruction.Args) >= 2 {
			return []string{instruction.Args[0], fmt.Sprintf("<%d chars>", len(instruction.Args[1]))}
		}
	case "img", "copy", "size", "cursor", "sync", "mouse", "key", "ack", "ready", "disconnect", "filesystem":
		return trimTraceArgs(instruction.Args, 10)
	}
	return trimTraceArgs(instruction.Args, 4)
}

func trimTraceArgs(args []string, limit int) []string {
	if len(args) <= limit {
		return args
	}
	out := append([]string{}, args[:limit]...)
	out = append(out, fmt.Sprintf("<+%d args>", len(args)-limit))
	return out
}

func (t Tunnel) handshake(conn net.Conn, reader *bufio.Reader, cfg DesktopConfig) error {
	protocol := strings.ToLower(string(cfg.Protocol))
	if protocol == "" {
		protocol = "rdp"
	}
	if _, err := conn.Write(Encode("select", protocol)); err != nil {
		return fmt.Errorf("send select: %w", err)
	}

	argsInstruction, raw, err := ReadInstruction(reader)
	if err != nil {
		return fmt.Errorf("read args: %w", err)
	}
	if argsInstruction.Opcode != "args" {
		return fmt.Errorf("expected guacd args, got %s (%s)", argsInstruction.Opcode, string(raw))
	}

	if _, err := conn.Write(Encode("size", strconv.Itoa(cfg.Width), strconv.Itoa(cfg.Height), strconv.Itoa(cfg.DPI))); err != nil {
		return fmt.Errorf("send size: %w", err)
	}
	if _, err := conn.Write(Encode("audio", "audio/L16", "rate=44100", "channels=2")); err != nil {
		return fmt.Errorf("send audio: %w", err)
	}
	if _, err := conn.Write(Encode("video")); err != nil {
		return fmt.Errorf("send video: %w", err)
	}
	if _, err := conn.Write(Encode("image", "image/png", "image/jpeg")); err != nil {
		return fmt.Errorf("send image: %w", err)
	}
	if _, err := conn.Write(Encode("timezone", "UTC")); err != nil {
		return fmt.Errorf("send timezone: %w", err)
	}

	values := make([]string, 0, len(argsInstruction.Args))
	for _, name := range argsInstruction.Args {
		values = append(values, t.argValue(name, cfg))
	}
	if _, err := conn.Write(Encode("connect", values...)); err != nil {
		return fmt.Errorf("send connect: %w", err)
	}
	return nil
}

func (t Tunnel) argValue(name string, cfg DesktopConfig) string {
	if strings.HasPrefix(name, "VERSION_") {
		return name
	}
	recordingPath := cfg.Session.RecordingPath
	drivePath := filepath.Join(t.DataDir, "drives", cfg.Session.ID)
	recordingEnabled := recordingPath != ""
	if cfg.Port == 0 {
		cfg.Port = defaultDesktopPort(cfg.Protocol)
	}
	if cfg.ColorDepth == 0 {
		cfg.ColorDepth = 24
	}
	if cfg.ResizeMethod == "" {
		cfg.ResizeMethod = "display-update"
	}
	// guacd often runs as a different OS user than openwebservermanager.
	// Session-scoped transfer/recording directories must be writable by that process.
	if recordingEnabled {
		_ = ensureGuacdWritableDir(recordingPath)
	}
	if cfg.EnableDrive {
		_ = ensureGuacdWritableDir(drivePath)
	}

	values := map[string]string{
		"hostname":                  cfg.Host,
		"port":                      strconv.Itoa(cfg.Port),
		"username":                  cfg.Username,
		"password":                  cfg.Password,
		"domain":                    cfg.Domain,
		"security":                  "any",
		"ignore-cert":               boolString(cfg.IgnoreCert),
		"color-depth":               strconv.Itoa(cfg.ColorDepth),
		"enable-wallpaper":          "false",
		"enable-theming":            "false",
		"disable-bitmap-caching":    "true",
		"disable-offscreen-caching": "true",
		"disable-glyph-caching":     "true",
		"initial-program":           "explorer.exe",
		"resize-method":             cfg.ResizeMethod,
		"enable-drive":              boolString(cfg.EnableDrive),
		"drive-name":                "openwebservermanager",
		"drive-path":                drivePath,
		"create-drive-path":         boolString(cfg.EnableDrive),
		"enable-recording":          boolString(recordingEnabled),
		"recording-path":            recordingPath,
		"create-recording-path":     boolString(recordingEnabled),
		"recording-name":            cfg.Session.ID,
		"recording-exclude-output":  "false",
		"recording-exclude-mouse":   "false",
		"recording-include-keys":    "false",
		"console":                   "false",
		"width":                     strconv.Itoa(cfg.Width),
		"height":                    strconv.Itoa(cfg.Height),
		"dpi":                       strconv.Itoa(cfg.DPI),
		"cursor":                    "remote",
		"read-only":                 boolString(cfg.ReadOnly),
		"disable-copy":              boolString(!cfg.ClipboardEnabled),
		"disable-paste":             boolString(!cfg.ClipboardEnabled),
		"swap-red-blue":             "false",
	}
	return values[name]
}

func defaultDesktopPort(protocol model.Protocol) int {
	if protocol == model.ProtocolVNC {
		return 5900
	}
	return 3389
}

func ensureGuacdWritableDir(path string) error {
	if path == "" {
		return nil
	}
	mode := sharedDirMode()
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}

func sharedDirMode() os.FileMode {
	value := strings.TrimSpace(envAny("OPENWEBSERVERMANAGER_SHARED_DIR_MODE", "SERVERMANAGER_SHARED_DIR_MODE"))
	if value == "" {
		return 0o770
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return 0o770
	}
	mode := os.FileMode(parsed) & 0o777
	if mode == 0 {
		return 0o770
	}
	return mode
}

func envAny(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func (t Tunnel) fail(sessionID string, err error) {
	if t.Logger != nil {
		t.Logger.Warn("desktop session failed", "session", sessionID, "error", err)
	}
	now := time.Now().UTC()
	_, _ = t.Store.UpdateSession(sessionID, func(item *model.ConnectionSession) {
		item.Status = model.SessionFailed
		item.Error = err.Error()
		item.EndedAt = &now
	})
}

func directorySize(path string) int64 {
	if path == "" {
		return 0
	}
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}
