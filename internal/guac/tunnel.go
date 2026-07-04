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

	"servermanager/internal/model"
	"servermanager/internal/store"
	"servermanager/internal/ws"
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

func (t Tunnel) Run(ctx context.Context, browser *ws.Conn, cfg RDPConfig) {
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
			payload, err := filterBrowserInstructions(payload, func(instruction Instruction, raw []byte) {
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
			_ = browser.SendText(Encode("nop"))
		}
	}
}

func filterBrowserInstructions(payload []byte, trace func(Instruction, []byte)) ([]byte, error) {
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
		out.Write(raw)
	}
	return out.Bytes(), nil
}

func (t Tunnel) newTrace(sessionID string) func(string, Instruction, int) {
	if os.Getenv("SERVERMANAGER_GUAC_TRACE") != "1" || t.Logger == nil {
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

func (t Tunnel) handshake(conn net.Conn, reader *bufio.Reader, cfg RDPConfig) error {
	if _, err := conn.Write(Encode("select", "rdp")); err != nil {
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

func (t Tunnel) argValue(name string, cfg RDPConfig) string {
	if strings.HasPrefix(name, "VERSION_") {
		return name
	}
	recordingPath := cfg.Session.RecordingPath
	drivePath := filepath.Join(t.DataDir, "drives", cfg.Session.ID)
	recordingEnabled := recordingPath != ""
	// guacd often runs as a different OS user than ServerManager.
	// Session-scoped transfer/recording directories must be writable by that process.
	if recordingEnabled {
		_ = ensureGuacdWritableDir(recordingPath)
	}
	_ = ensureGuacdWritableDir(drivePath)

	values := map[string]string{
		"hostname":                  cfg.Server.Host,
		"port":                      strconv.Itoa(cfg.Server.RDPPort),
		"username":                  cfg.Credential.Username,
		"password":                  cfg.Secret.Password,
		"domain":                    cfg.Credential.Domain,
		"security":                  "any",
		"ignore-cert":               "true",
		"color-depth":               "24",
		"enable-wallpaper":          "false",
		"enable-theming":            "false",
		"disable-bitmap-caching":    "true",
		"disable-offscreen-caching": "true",
		"disable-glyph-caching":     "true",
		"initial-program":           "explorer.exe",
		"resize-method":             "display-update",
		"enable-drive":              "true",
		"drive-name":                "ServerManager",
		"drive-path":                drivePath,
		"create-drive-path":         "true",
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
	}
	return values[name]
}

func ensureGuacdWritableDir(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o777); err != nil {
		return err
	}
	return os.Chmod(path, 0o777)
}

func boolString(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func (t Tunnel) fail(sessionID string, err error) {
	if t.Logger != nil {
		t.Logger.Warn("rdp session failed", "session", sessionID, "error", err)
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
