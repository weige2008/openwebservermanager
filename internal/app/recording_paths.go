package app

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

func (s *Server) migrateLegacyRecordingPaths() {
	if s.cfg.Store == nil {
		return
	}
	migratedDirectories := map[string]string{}
	migratePath := func(path string) (string, bool) {
		path = strings.TrimSpace(path)
		if path == "" {
			return "", false
		}
		if migrated, ok := migratedDirectories[path]; ok {
			return migrated, migrated != ""
		}
		target, ok, err := s.migrateLegacyRecordingDirectory(path)
		if err != nil {
			slog.Warn("legacy recording path migration failed", "path", path, "error", err)
			migratedDirectories[path] = ""
			return "", false
		}
		if !ok {
			migratedDirectories[path] = ""
			return "", false
		}
		migratedDirectories[path] = target
		return target, true
	}

	_, _, sessions, _ := s.cfg.Store.Bootstrap()
	for _, session := range sessions {
		target, ok := migratePath(session.RecordingPath)
		if !ok || target == session.RecordingPath {
			continue
		}
		if _, err := s.cfg.Store.UpdateSession(session.ID, func(item *model.ConnectionSession) {
			item.RecordingPath = target
		}); err != nil {
			slog.Warn("persist legacy session recording path migration failed", "session_id", session.ID, "error", err)
			continue
		}
		s.writeRecordingPathMigrationLog(session.ID, session.UserID, session.Protocol, session.RecordingPath, target)
	}

	offline, err := s.cfg.Store.ListPlatformItems("offline_sessions")
	if err != nil {
		return
	}
	for _, item := range offline {
		previous := firstMetadataString(item.Metadata, "recording_path")
		target, ok := migratePath(previous)
		if !ok || target == previous {
			continue
		}
		item.Metadata = cloneMetadata(item.Metadata)
		item.Metadata["recording_path"] = target
		item.Metadata["recording_path_migrated_at"] = time.Now().UTC()
		if _, err := s.cfg.Store.SavePlatformItem("offline_sessions", item); err != nil {
			slog.Warn("persist legacy offline recording path migration failed", "session_id", item.ID, "error", err)
			continue
		}
		s.writeRecordingPathMigrationLog(item.ID, item.OwnerID, item.Protocol, previous, target)
	}
}

func (s *Server) migrateLegacyRecordingDirectory(recordingPath string) (string, bool, error) {
	dataDir := strings.TrimSpace(s.cfg.DataDir)
	if dataDir == "" {
		dataDir = "data"
	}
	currentRoot, err := filepath.Abs(filepath.Join(dataDir, "recordings"))
	if err != nil {
		return "", false, err
	}
	if err := ensureChildPath(currentRoot, recordingPath); err == nil {
		return recordingPath, false, nil
	} else if !errors.Is(err, errStoragePathEscape) {
		return "", false, err
	}
	dataDirAbs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", false, err
	}
	legacyRoot := filepath.Join(filepath.Dir(filepath.Dir(dataDirAbs)), "servermanager", "data", "recordings")
	if err := ensureChildPath(legacyRoot, recordingPath); err != nil {
		return "", false, nil
	}
	relative, err := filepath.Rel(legacyRoot, recordingPath)
	if err != nil {
		return "", false, err
	}
	target := filepath.Join(currentRoot, relative)
	if err := ensureChildPath(currentRoot, target); err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(currentRoot, 0o770); err != nil {
		return "", false, err
	}
	if err := ensureExistingRealStorageDirectory(currentRoot, target); err == nil {
		return target, true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", false, err
	}
	if err := ensureExistingRealStorageDirectory(legacyRoot, recordingPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	if err := copyDirectory(recordingPath, target); err != nil {
		return "", false, err
	}
	return target, true, nil
}

func (s *Server) writeRecordingPathMigrationLog(id, ownerID string, protocol model.Protocol, previous, target string) {
	_, _ = s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        "recording.path.migrated",
		Type:        "recording",
		Status:      "success",
		Protocol:    protocol,
		TargetID:    id,
		OwnerID:     ownerID,
		Description: "migrated legacy recording path",
		Metadata: map[string]any{
			"previous_path":  previous,
			"recording_path": target,
		},
	})
}
