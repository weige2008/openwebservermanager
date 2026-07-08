package app

import (
	"archive/zip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"openwebservermanager/internal/model"
)

var errUnsupportedScheduledTaskType = errors.New("scheduled task type is not supported")

func (s *Server) runScheduledTask(_ *http.Request, task model.PlatformItem) (string, map[string]any, error) {
	switch normalizeScheduledTaskType(task.Type) {
	case "backup":
		metadata, err := s.createBackupSnapshot()
		return "backup completed", metadata, err
	case "log-cleanup":
		metadata, err := s.cleanupHistoryLogs(task)
		return "log cleanup completed", metadata, err
	case "asset-status":
		metadata, err := s.checkAssetStatuses(task)
		return "asset status check completed", metadata, err
	case "certificate-renewal":
		metadata, err := s.renewDueSelfSignedCertificates(task)
		return "certificate renewal completed", metadata, err
	default:
		taskType := normalizeScheduledTaskType(task.Type)
		if taskType == "" {
			taskType = "(empty)"
		}
		message := "scheduled task type is not supported: " + taskType
		return message, map[string]any{"supported": false, "message": message}, fmt.Errorf("%w: %s", errUnsupportedScheduledTaskType, taskType)
	}
}

func (s *Server) executeScheduledTask(r *http.Request, task model.PlatformItem, trigger string) (model.PlatformItem, error) {
	taskType := normalizeScheduledTaskType(task.Type)
	if taskType == "log-cleanup" {
		return s.executeLogCleanupScheduledTask(r, task, trigger)
	}
	if scheduledTaskNeedsPreRunLog(taskType) {
		return s.executePreLoggedScheduledTask(r, task, trigger)
	}
	if trigger == "" {
		trigger = "manual"
	}
	started := time.Now().UTC()
	result, metadata, runErr := s.runScheduledTask(r, task)
	if metadata == nil {
		metadata = map[string]any{}
	}
	completed := time.Now().UTC()
	status := "success"
	if runErr != nil {
		status = "failed"
		metadata["error"] = runErr.Error()
		if result == "" {
			result = runErr.Error()
		}
	}
	metadata["task_type"] = task.Type
	metadata["trigger"] = trigger
	metadata["ran_at"] = started
	metadata["completed_at"] = completed
	metadata["duration_ms"] = completed.Sub(started).Milliseconds()
	if trigger == "scheduled" {
		metadata["owner_id"] = "system"
	}
	ownerID := "system"
	if r != nil {
		ownerID = s.currentUserID(r)
	}
	logItem, logErr := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        task.Name,
		Type:        "scheduled_task",
		Status:      status,
		TargetID:    task.ID,
		OwnerID:     ownerID,
		Description: result,
		Metadata:    metadata,
	})
	if logErr != nil {
		detail := "persist scheduled task log failed: " + logErr.Error()
		_ = s.audit(r, "scheduled_task.log.persist_failed", task.ID, "", detail)
		if cleanupErr := s.cleanupScheduledTaskArtifactsAfterLogFailure(task, metadata); cleanupErr != nil {
			detail += "; additionally failed to clean up scheduled task artifacts: " + cleanupErr.Error()
		}
		if runErr != nil {
			return model.PlatformItem{}, fmt.Errorf("%w; additionally %s", runErr, detail)
		}
		return model.PlatformItem{}, errors.New(detail)
	}
	nextMetadata := cloneMetadata(task.Metadata)
	nextMetadata["last_run_at"] = completed.Format(time.RFC3339Nano)
	nextMetadata["last_run_status"] = status
	nextMetadata["last_run_message"] = result
	nextMetadata["last_run_log_id"] = logItem.ID
	nextMetadata["last_duration_ms"] = completed.Sub(started).Milliseconds()
	nextMetadata["last_trigger"] = trigger
	if runErr != nil {
		nextMetadata["last_run_error"] = runErr.Error()
	} else {
		delete(nextMetadata, "last_run_error")
	}
	if nextRun, ok := nextScheduledTaskRunAfter(task, completed); ok {
		nextMetadata["next_run_at"] = nextRun.Format(time.RFC3339Nano)
	} else {
		delete(nextMetadata, "next_run_at")
	}
	if _, updateErr := s.cfg.Store.UpdatePlatformItem("scheduled_tasks", task.ID, model.PlatformItemRequest{Metadata: nextMetadata}); updateErr != nil {
		detail := "persist scheduled task state failed: " + updateErr.Error()
		_ = s.audit(r, "scheduled_task.state.persist_failed", task.ID, "", detail)
		if runErr != nil {
			return logItem, fmt.Errorf("%w; additionally %s", runErr, detail)
		}
		return logItem, errors.New(detail)
	}
	if runErr != nil {
		return logItem, runErr
	}
	return logItem, nil
}

func scheduledTaskNeedsPreRunLog(taskType string) bool {
	switch taskType {
	case "asset-status", "certificate-renewal":
		return true
	default:
		return false
	}
}

type scheduledTaskCollectionSnapshot struct {
	Collection string
	Items      []model.PlatformItem
}

func (s *Server) scheduledTaskMutationSnapshot(taskType string) ([]scheduledTaskCollectionSnapshot, error) {
	switch taskType {
	case "asset-status":
		return s.platformCollectionsSnapshot([]string{"assets", "web_assets", "database_assets"})
	case "certificate-renewal":
		return s.platformCollectionsSnapshot([]string{"certificates"})
	default:
		return nil, nil
	}
}

func (s *Server) platformCollectionsSnapshot(collections []string) ([]scheduledTaskCollectionSnapshot, error) {
	snapshot := make([]scheduledTaskCollectionSnapshot, 0, len(collections))
	for _, collection := range collections {
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			return nil, err
		}
		collectionSnapshot := scheduledTaskCollectionSnapshot{Collection: collection}
		for _, item := range items {
			raw, ok, err := s.cfg.Store.GetPlatformItem(collection, item.ID)
			if err != nil {
				return nil, err
			}
			if ok {
				collectionSnapshot.Items = append(collectionSnapshot.Items, raw)
			}
		}
		snapshot = append(snapshot, collectionSnapshot)
	}
	return snapshot, nil
}

func (s *Server) restoreScheduledTaskMutationSnapshot(snapshot []scheduledTaskCollectionSnapshot) error {
	for _, collectionSnapshot := range snapshot {
		for _, item := range collectionSnapshot.Items {
			if _, err := s.cfg.Store.SavePlatformItem(collectionSnapshot.Collection, item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) executePreLoggedScheduledTask(r *http.Request, task model.PlatformItem, trigger string) (model.PlatformItem, error) {
	if trigger == "" {
		trigger = "manual"
	}
	taskType := normalizeScheduledTaskType(task.Type)
	mutationSnapshot, err := s.scheduledTaskMutationSnapshot(taskType)
	if err != nil {
		return model.PlatformItem{}, err
	}
	started := time.Now().UTC()
	ownerID := "system"
	if r != nil {
		ownerID = s.currentUserID(r)
	}
	runningMetadata := map[string]any{
		"task_type": task.Type,
		"trigger":   trigger,
		"ran_at":    started,
	}
	if trigger == "scheduled" {
		runningMetadata["owner_id"] = "system"
	}
	logItem, logErr := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        task.Name,
		Type:        "scheduled_task",
		Status:      "running",
		TargetID:    task.ID,
		OwnerID:     ownerID,
		Description: "running scheduled task",
		Metadata:    runningMetadata,
	})
	if logErr != nil {
		detail := "persist scheduled task log failed: " + logErr.Error()
		_ = s.audit(r, "scheduled_task.log.persist_failed", task.ID, "", detail)
		return model.PlatformItem{}, errors.New(detail)
	}

	result, metadata, runErr := s.runScheduledTask(r, task)
	if metadata == nil {
		metadata = map[string]any{}
	}
	completed := time.Now().UTC()
	status := "success"
	if runErr != nil {
		status = "failed"
		metadata["error"] = runErr.Error()
		if result == "" {
			result = runErr.Error()
		}
	}
	metadata["task_type"] = task.Type
	metadata["trigger"] = trigger
	metadata["ran_at"] = started
	metadata["completed_at"] = completed
	metadata["duration_ms"] = completed.Sub(started).Milliseconds()
	if trigger == "scheduled" {
		metadata["owner_id"] = "system"
	}
	logItem, logErr = s.cfg.Store.UpdatePlatformItem("operation_logs", logItem.ID, model.PlatformItemRequest{
		Status:      status,
		Description: result,
		Metadata:    metadata,
	})
	if logErr != nil {
		detail := "persist scheduled task log failed: " + logErr.Error()
		_ = s.audit(r, "scheduled_task.log.persist_failed", task.ID, "", detail)
		if restoreErr := s.restoreScheduledTaskMutationSnapshot(mutationSnapshot); restoreErr != nil {
			detail += "; additionally failed to restore scheduled task mutations: " + restoreErr.Error()
			_ = s.audit(r, "scheduled_task.restore_failed", task.ID, "", detail)
		}
		if runErr != nil {
			return logItem, fmt.Errorf("%w; additionally %s", runErr, detail)
		}
		return logItem, errors.New(detail)
	}

	nextMetadata := cloneMetadata(task.Metadata)
	nextMetadata["last_run_at"] = completed.Format(time.RFC3339Nano)
	nextMetadata["last_run_status"] = status
	nextMetadata["last_run_message"] = result
	nextMetadata["last_run_log_id"] = logItem.ID
	nextMetadata["last_duration_ms"] = completed.Sub(started).Milliseconds()
	nextMetadata["last_trigger"] = trigger
	if runErr != nil {
		nextMetadata["last_run_error"] = runErr.Error()
	} else {
		delete(nextMetadata, "last_run_error")
	}
	if nextRun, ok := nextScheduledTaskRunAfter(task, completed); ok {
		nextMetadata["next_run_at"] = nextRun.Format(time.RFC3339Nano)
	} else {
		delete(nextMetadata, "next_run_at")
	}
	if _, updateErr := s.cfg.Store.UpdatePlatformItem("scheduled_tasks", task.ID, model.PlatformItemRequest{Metadata: nextMetadata}); updateErr != nil {
		detail := "persist scheduled task state failed: " + updateErr.Error()
		_ = s.audit(r, "scheduled_task.state.persist_failed", task.ID, "", detail)
		if runErr != nil {
			return logItem, fmt.Errorf("%w; additionally %s", runErr, detail)
		}
		return logItem, errors.New(detail)
	}
	if runErr != nil {
		return logItem, runErr
	}
	return logItem, nil
}

func (s *Server) executeLogCleanupScheduledTask(r *http.Request, task model.PlatformItem, trigger string) (model.PlatformItem, error) {
	if trigger == "" {
		trigger = "manual"
	}
	started := time.Now().UTC()
	ownerID := "system"
	if r != nil {
		ownerID = s.currentUserID(r)
	}
	runningMetadata := map[string]any{
		"task_type": task.Type,
		"trigger":   trigger,
		"ran_at":    started,
	}
	if trigger == "scheduled" {
		runningMetadata["owner_id"] = "system"
	}
	logItem, logErr := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name:        task.Name,
		Type:        "scheduled_task",
		Status:      "running",
		TargetID:    task.ID,
		OwnerID:     ownerID,
		Description: "running log cleanup",
		Metadata:    runningMetadata,
	})
	if logErr != nil {
		detail := "persist scheduled task log failed: " + logErr.Error()
		_ = s.audit(r, "scheduled_task.log.persist_failed", task.ID, "", detail)
		return model.PlatformItem{}, errors.New(detail)
	}

	cleanupSnapshot, err := s.logCleanupSnapshot()
	if err != nil {
		return logItem, err
	}
	defer cleanupSnapshot.cleanup()
	result := "log cleanup completed"
	metadata, runErr := s.cleanupHistoryLogs(task, logItem.ID)
	if metadata == nil {
		metadata = map[string]any{}
	}
	completed := time.Now().UTC()
	status := "success"
	if runErr != nil {
		status = "failed"
		metadata["error"] = runErr.Error()
		result = runErr.Error()
	}
	metadata["task_type"] = task.Type
	metadata["trigger"] = trigger
	metadata["ran_at"] = started
	metadata["completed_at"] = completed
	metadata["duration_ms"] = completed.Sub(started).Milliseconds()
	if trigger == "scheduled" {
		metadata["owner_id"] = "system"
	}
	logItem, logErr = s.cfg.Store.UpdatePlatformItem("operation_logs", logItem.ID, model.PlatformItemRequest{
		Status:      status,
		Description: result,
		Metadata:    metadata,
	})
	if logErr != nil {
		detail := "persist scheduled task log failed: " + logErr.Error()
		_ = s.audit(r, "scheduled_task.log.persist_failed", task.ID, "", detail)
		if restoreErr := s.restoreLogCleanupSnapshot(cleanupSnapshot); restoreErr != nil {
			detail += "; additionally failed to restore log cleanup mutations: " + restoreErr.Error()
			_ = s.audit(r, "scheduled_task.restore_failed", task.ID, "", detail)
		}
		if runErr != nil {
			return logItem, fmt.Errorf("%w; additionally %s", runErr, detail)
		}
		return logItem, errors.New(detail)
	}

	nextMetadata := cloneMetadata(task.Metadata)
	nextMetadata["last_run_at"] = completed.Format(time.RFC3339Nano)
	nextMetadata["last_run_status"] = status
	nextMetadata["last_run_message"] = result
	nextMetadata["last_run_log_id"] = logItem.ID
	nextMetadata["last_duration_ms"] = completed.Sub(started).Milliseconds()
	nextMetadata["last_trigger"] = trigger
	if runErr != nil {
		nextMetadata["last_run_error"] = runErr.Error()
	} else {
		delete(nextMetadata, "last_run_error")
	}
	if nextRun, ok := nextScheduledTaskRunAfter(task, completed); ok {
		nextMetadata["next_run_at"] = nextRun.Format(time.RFC3339Nano)
	} else {
		delete(nextMetadata, "next_run_at")
	}
	if _, updateErr := s.cfg.Store.UpdatePlatformItem("scheduled_tasks", task.ID, model.PlatformItemRequest{Metadata: nextMetadata}); updateErr != nil {
		detail := "persist scheduled task state failed: " + updateErr.Error()
		_ = s.audit(r, "scheduled_task.state.persist_failed", task.ID, "", detail)
		if runErr != nil {
			return logItem, fmt.Errorf("%w; additionally %s", runErr, detail)
		}
		return logItem, errors.New(detail)
	}
	if runErr != nil {
		return logItem, runErr
	}
	return logItem, nil
}

type logCleanupMutationSnapshot struct {
	PlatformItems []scheduledTaskCollectionSnapshot
	Sessions      []model.ConnectionSession
	Recordings    []recordingDirectorySnapshot
}

type recordingDirectorySnapshot struct {
	Path       string
	BackupDir  string
	BackupPath string
}

func (s *Server) logCleanupSnapshot() (logCleanupMutationSnapshot, error) {
	collections := []string{"login_logs", "operation_logs", "file_logs", "access_logs", "sql_logs", "exec_command_logs", "offline_sessions"}
	platformItems, err := s.platformCollectionsSnapshot(collections)
	if err != nil {
		return logCleanupMutationSnapshot{}, err
	}
	_, _, sessions, _ := s.cfg.Store.Bootstrap()
	offlineItems := []model.PlatformItem{}
	for _, collectionSnapshot := range platformItems {
		if collectionSnapshot.Collection == "offline_sessions" {
			offlineItems = collectionSnapshot.Items
			break
		}
	}
	recordings, err := s.snapshotLogCleanupRecordings(sessions, offlineItems)
	if err != nil {
		for _, recording := range recordings {
			recording.cleanup()
		}
		return logCleanupMutationSnapshot{}, err
	}
	return logCleanupMutationSnapshot{
		PlatformItems: platformItems,
		Sessions:      sessions,
		Recordings:    recordings,
	}, nil
}

func (s *Server) snapshotLogCleanupRecordings(sessions []model.ConnectionSession, offlineItems []model.PlatformItem) ([]recordingDirectorySnapshot, error) {
	seen := map[string]bool{}
	paths := []string{}
	addPath := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		paths = append(paths, path)
	}
	for _, session := range sessions {
		addPath(session.RecordingPath)
	}
	for _, item := range offlineItems {
		addPath(firstMetadataString(item.Metadata, "recording_path"))
	}
	result := []recordingDirectorySnapshot{}
	for _, path := range paths {
		snapshot, ok, err := s.snapshotRecordingDirectory(path)
		if err != nil {
			return result, err
		}
		if ok {
			result = append(result, snapshot)
		}
	}
	return result, nil
}

func (s *Server) snapshotRecordingDirectory(recordingPath string) (recordingDirectorySnapshot, bool, error) {
	path, err := s.recordingDirectory(recordingPath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errStorageSpecialFile) {
		return recordingDirectorySnapshot{}, false, nil
	}
	if err != nil {
		return recordingDirectorySnapshot{}, false, err
	}
	backupDir, err := os.MkdirTemp("", "openwebservermanager-recording-rollback-*")
	if err != nil {
		return recordingDirectorySnapshot{}, false, err
	}
	backupPath := filepath.Join(backupDir, "recording")
	if err := copyDirectory(path, backupPath); err != nil {
		_ = os.RemoveAll(backupDir)
		return recordingDirectorySnapshot{}, false, err
	}
	return recordingDirectorySnapshot{Path: path, BackupDir: backupDir, BackupPath: backupPath}, true, nil
}

func (s *Server) restoreLogCleanupSnapshot(snapshot logCleanupMutationSnapshot) error {
	for _, recording := range snapshot.Recordings {
		if err := s.restoreRecordingDirectorySnapshot(recording); err != nil {
			return err
		}
	}
	for _, session := range snapshot.Sessions {
		if _, err := s.cfg.Store.SaveSession(session); err != nil {
			return err
		}
	}
	for _, collectionSnapshot := range snapshot.PlatformItems {
		for _, item := range collectionSnapshot.Items {
			if _, err := s.cfg.Store.SavePlatformItem(collectionSnapshot.Collection, item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Server) restoreRecordingDirectorySnapshot(snapshot recordingDirectorySnapshot) error {
	if snapshot.Path == "" || snapshot.BackupPath == "" {
		return nil
	}
	root := filepath.Join(s.cfg.DataDir, "recordings")
	if err := ensureChildPath(root, snapshot.Path); err != nil {
		return err
	}
	if err := os.RemoveAll(snapshot.Path); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(snapshot.Path), 0o770); err != nil {
		return err
	}
	return copyDirectory(snapshot.BackupPath, snapshot.Path)
}

func (snapshot logCleanupMutationSnapshot) cleanup() {
	for _, recording := range snapshot.Recordings {
		recording.cleanup()
	}
}

func (snapshot recordingDirectorySnapshot) cleanup() {
	if snapshot.BackupDir != "" {
		_ = os.RemoveAll(snapshot.BackupDir)
	}
}

func (s *Server) cleanupScheduledTaskArtifactsAfterLogFailure(task model.PlatformItem, metadata map[string]any) error {
	if normalizeScheduledTaskType(task.Type) != "backup" {
		return nil
	}
	backupPath := firstMetadataString(metadata, "backup_path")
	if backupPath == "" {
		return nil
	}
	return s.removeBackupArtifact(backupPath)
}

func (s *Server) removeBackupArtifact(path string) error {
	path = filepath.FromSlash(strings.TrimSpace(path))
	if path == "" {
		return nil
	}
	backupRoot := filepath.Join(s.cfg.DataDir, "backups")
	if err := ensureChildPath(backupRoot, path); err != nil {
		return err
	}
	if _, err := backupRegularFileInfo(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return os.Remove(path)
}

func normalizeScheduledTaskType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	return value
}

func (s *Server) createBackupSnapshot() (map[string]any, error) {
	return s.createBackupSnapshotWithRetentionCleanup(s.cleanupExpiredBackups)
}

func (s *Server) createBackupSnapshotWithRetentionCleanup(cleanup func(time.Time) (backupRetentionResult, error)) (_ map[string]any, err error) {
	backupDir := filepath.Join(s.cfg.DataDir, "backups")
	if err := os.MkdirAll(backupDir, 0o770); err != nil {
		return nil, err
	}
	target, output, err := createBackupSnapshotFile(backupDir, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		_ = output.Close()
		_ = os.Remove(target)
	}()
	archive := zip.NewWriter(output)
	files := []string{}
	storePath := s.cfg.Store.Path()
	if err := addBackupFile(archive, storePath, filepath.Base(storePath)); err == nil {
		files = append(files, filepath.Base(storePath))
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = archive.Close()
		_ = output.Close()
		return nil, err
	}
	dbPath := strings.TrimSuffix(storePath, filepath.Ext(storePath)) + ".db"
	if err := addBackupFile(archive, dbPath, filepath.Base(dbPath)); err == nil {
		files = append(files, filepath.Base(dbPath))
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = archive.Close()
		_ = output.Close()
		return nil, err
	}
	manifest := map[string]any{"created_at": time.Now().UTC(), "files": files}
	manifestWriter, err := archive.Create("manifest.json")
	if err != nil {
		_ = archive.Close()
		_ = output.Close()
		return nil, err
	}
	_ = json.NewEncoder(manifestWriter).Encode(manifest)
	if err := archive.Close(); err != nil {
		_ = output.Close()
		return nil, err
	}
	if err := output.Close(); err != nil {
		return nil, err
	}
	info, err := os.Stat(target)
	if err != nil {
		return nil, err
	}
	retention, err := cleanup(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"backup_path":       filepath.ToSlash(target),
		"backup_size":       info.Size(),
		"files":             files,
		"retention":         retention,
		"retention_deleted": retention.DeletedCount,
	}, nil
}

func createBackupSnapshotFile(backupDir string, now time.Time) (string, *os.File, error) {
	for attempt := 0; attempt < 100; attempt++ {
		name := backupSnapshotFilename(now, attempt)
		target := filepath.Join(backupDir, name)
		output, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o660)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		return target, output, err
	}
	return "", nil, fmt.Errorf("create unique backup file in %s: exhausted filename attempts", backupDir)
}

func backupSnapshotFilename(now time.Time, attempt int) string {
	now = now.UTC()
	stamp := fmt.Sprintf("%s-%09d", now.Format("20060102-150405"), now.Nanosecond())
	if attempt > 0 {
		stamp = fmt.Sprintf("%s-%02d", stamp, attempt)
	}
	return "backup-" + stamp + ".zip"
}

func addBackupFile(archive *zip.Writer, source, name string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	writer, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(writer, input)
	return err
}

func (s *Server) cleanupHistoryLogs(task model.PlatformItem, preservedOperationLogIDs ...string) (map[string]any, error) {
	settings := s.retentionSettings()
	collections := []string{"login_logs", "operation_logs", "file_logs", "access_logs", "sql_logs", "exec_command_logs"}
	preservedOperationLogs := map[string]bool{}
	for _, id := range preservedOperationLogIDs {
		id = strings.TrimSpace(id)
		if id != "" {
			preservedOperationLogs[id] = true
		}
	}
	deletedByCollection := map[string]int{}
	totalDeleted := 0
	now := time.Now().UTC()
	for _, collection := range collections {
		days := retentionDaysForCollection(collection, task.Metadata, settings, 90)
		cutoff := now.AddDate(0, 0, -days)
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if collection == "operation_logs" && preservedOperationLogs[item.ID] {
				continue
			}
			if item.CreatedAt.IsZero() || item.CreatedAt.After(cutoff) {
				continue
			}
			if err := s.cfg.Store.DeletePlatformItem(collection, item.ID); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return nil, err
			}
			deletedByCollection[collection]++
			totalDeleted++
		}
	}
	sessionCleanup, err := s.cleanupExpiredConnectionSessions(task.Metadata, settings, now)
	if err != nil {
		return nil, err
	}
	deletedByCollection["connection_sessions"] = sessionCleanup.DeletedSessions
	deletedByCollection["offline_sessions"] = sessionCleanup.DeletedOfflineRecords
	totalDeleted += sessionCleanup.DeletedSessions + sessionCleanup.DeletedOfflineRecords
	return map[string]any{
		"deleted_count":          totalDeleted,
		"deleted":                deletedByCollection,
		"recordings_deleted":     sessionCleanup.DeletedRecordings,
		"recording_bytes":        sessionCleanup.DeletedRecordingBytes,
		"session_retention_days": sessionCleanup.RetentionDays,
	}, nil
}

type sessionCleanupResult struct {
	RetentionDays         int
	DeletedSessions       int
	DeletedOfflineRecords int
	DeletedRecordings     int
	DeletedRecordingBytes int64
}

func (s *Server) cleanupExpiredConnectionSessions(taskMetadata, settings map[string]any, now time.Time) (sessionCleanupResult, error) {
	days := sessionRetentionDays(taskMetadata, settings, 90)
	cutoff := now.AddDate(0, 0, -days)
	result := sessionCleanupResult{RetentionDays: days}
	_, _, sessions, _ := s.cfg.Store.Bootstrap()
	for _, session := range sessions {
		if session.Status == model.SessionActive || session.Status == model.SessionPending {
			continue
		}
		if retentionTime := connectionSessionRetentionTime(session); retentionTime.IsZero() || retentionTime.After(cutoff) {
			continue
		}
		recordingDeleted, recordingBytes, err := s.deleteSessionRecordingPath(session.RecordingPath)
		if err != nil {
			return result, err
		}
		if recordingDeleted {
			result.DeletedRecordings++
			result.DeletedRecordingBytes += recordingBytes
		}
		if err := s.cfg.Store.DeleteSession(session.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		result.DeletedSessions++
	}
	offline, err := s.cfg.Store.ListPlatformItems("offline_sessions")
	if err != nil {
		return result, err
	}
	for _, item := range offline {
		if retentionTime := offlineSessionRetentionTime(item); retentionTime.IsZero() || retentionTime.After(cutoff) {
			continue
		}
		recordingDeleted, recordingBytes, err := s.deleteSessionRecordingPath(firstMetadataString(item.Metadata, "recording_path"))
		if err != nil {
			return result, err
		}
		if recordingDeleted {
			result.DeletedRecordings++
			result.DeletedRecordingBytes += recordingBytes
		}
		if err := s.cfg.Store.DeletePlatformItem("offline_sessions", item.ID); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, err
		}
		result.DeletedOfflineRecords++
	}
	return result, nil
}

func sessionRetentionDays(taskMetadata, settings map[string]any, fallback int) int {
	keys := []string{
		"connection_sessions_days",
		"connection_session_days",
		"sessions_days",
		"session_days",
		"offline_sessions_days",
		"offline_session_days",
		"recordings_days",
		"recording_days",
		"retention_days",
		"days",
	}
	for _, key := range keys {
		if value, ok := metadataInt(taskMetadata[key]); ok {
			return maxInt(value, 0)
		}
	}
	for _, key := range keys {
		if value, ok := metadataInt(settings[key]); ok {
			return maxInt(value, 0)
		}
	}
	return fallback
}

func connectionSessionRetentionTime(session model.ConnectionSession) time.Time {
	if session.EndedAt != nil && !session.EndedAt.IsZero() {
		return session.EndedAt.UTC()
	}
	if !session.LastActivityAt.IsZero() {
		return session.LastActivityAt.UTC()
	}
	return session.StartedAt.UTC()
}

func offlineSessionRetentionTime(item model.PlatformItem) time.Time {
	if value, ok := metadataTime(item.Metadata["ended_at"]); ok {
		return value.UTC()
	}
	if !item.UpdatedAt.IsZero() {
		return item.UpdatedAt.UTC()
	}
	return item.CreatedAt.UTC()
}

func (s *Server) deleteSessionRecordingPath(recordingPath string) (bool, int64, error) {
	recordingPath = strings.TrimSpace(recordingPath)
	if recordingPath == "" {
		return false, 0, nil
	}
	path, err := s.recordingDirectory(recordingPath)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, errStorageSpecialFile) {
		return false, 0, nil
	}
	if err != nil {
		return false, 0, err
	}
	size := int64(0)
	if value, ok := directoryUsage(path)["bytes"].(int64); ok {
		size = value
	}
	if err := os.RemoveAll(path); err != nil {
		return false, 0, err
	}
	return true, size, nil
}

func (s *Server) retentionSettings() map[string]any {
	items, err := s.cfg.Store.ListPlatformItems("system_settings")
	if err != nil {
		return nil
	}
	for _, item := range items {
		if strings.EqualFold(item.Type, "retention") {
			return item.Metadata
		}
	}
	return nil
}

func retentionDaysForCollection(collection string, taskMetadata, settings map[string]any, fallback int) int {
	keys := []string{collection + "_days", strings.TrimSuffix(collection, "_logs") + "_days", "retention_days", "days"}
	for _, key := range keys {
		if value, ok := metadataInt(taskMetadata[key]); ok {
			return maxInt(value, 0)
		}
	}
	for _, key := range keys {
		if value, ok := metadataInt(settings[key]); ok {
			return maxInt(value, 0)
		}
	}
	return fallback
}

func (s *Server) checkAssetStatuses(task model.PlatformItem) (map[string]any, error) {
	timeout := time.Duration(clampInt(metadataIntDefault(task.Metadata["timeout_ms"], 2000), 100, 30000, 2000)) * time.Millisecond
	collections := []string{"assets", "web_assets", "database_assets"}
	checked := 0
	active := 0
	offline := 0
	skipped := 0
	results := []map[string]any{}
	now := time.Now().UTC()
	for _, collection := range collections {
		items, err := s.cfg.Store.ListPlatformItems(collection)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if strings.EqualFold(strings.TrimSpace(item.Status), "disabled") {
				skipped++
				continue
			}
			checked++
			started := time.Now()
			status, detail := s.checkAssetReachability(collection, item, timeout)
			latency := time.Since(started).Milliseconds()
			if status == "active" {
				active++
			} else {
				offline++
			}
			nextMetadata := map[string]any{}
			for key, value := range item.Metadata {
				nextMetadata[key] = value
			}
			nextMetadata["last_check_at"] = now
			nextMetadata["last_check_status"] = status
			nextMetadata["last_check_detail"] = detail
			nextMetadata["last_check_latency_ms"] = latency
			persisted := true
			if isLegacyMirroredAsset(collection, item) {
				persisted = false
			} else {
				_, err := s.cfg.Store.UpdatePlatformItem(collection, item.ID, model.PlatformItemRequest{
					Status:   status,
					Metadata: nextMetadata,
				})
				if err != nil {
					return nil, err
				}
			}
			result := map[string]any{
				"id":         item.ID,
				"name":       item.Name,
				"collection": collection,
				"status":     status,
				"detail":     detail,
				"latency_ms": latency,
				"persisted":  persisted,
			}
			if !persisted {
				result["source"] = "legacy_server"
			}
			results = append(results, result)
		}
	}
	return map[string]any{
		"checked": checked,
		"active":  active,
		"offline": offline,
		"skipped": skipped,
		"results": results,
	}, nil
}

func isLegacyMirroredAsset(collection string, item model.PlatformItem) bool {
	return collection == "assets" && strings.EqualFold(firstMetadataString(item.Metadata, "source"), "legacy_server")
}

func (s *Server) checkAssetReachability(collection string, item model.PlatformItem, timeout time.Duration) (string, string) {
	switch collection {
	case "web_assets":
		if raw, ok, err := s.cfg.Store.GetPlatformItem("web_assets", item.ID); err != nil {
			return "offline", err.Error()
		} else if ok {
			item = raw
		}
		if err := s.decryptWebAssetUpstreamURL(&item); err != nil {
			return "offline", err.Error()
		}
		target, err := webAssetTargetURL(item)
		if err != nil {
			return "offline", err.Error()
		}
		return checkWebAssetReachability(target.String(), timeout)
	case "database_assets":
		connection, err := s.databaseAssetConnection(item)
		if err != nil {
			return "offline", err.Error()
		}
		if connection.Driver == "sqlite" {
			return checkSQLiteDatabaseAssetReachability(connection.DSN)
		}
		db, err := sql.Open(connection.Driver, connection.DSN)
		if err != nil {
			return "offline", err.Error()
		}
		defer db.Close()
		if err := db.Ping(); err != nil {
			return "offline", err.Error()
		}
		return "active", connection.Driver
	default:
		host := strings.TrimSpace(item.Host)
		if host == "" {
			return "offline", "host is empty"
		}
		port := item.Port
		if port == 0 {
			port = defaultProtocolPort(item.Protocol)
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
		if err != nil {
			return "offline", err.Error()
		}
		_ = conn.Close()
		return "active", fmt.Sprintf("%s:%d reachable", host, port)
	}
}

func checkSQLiteDatabaseAssetReachability(path string) (string, string) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "offline", "sqlite database file not found"
	}
	if err != nil {
		return "offline", err.Error()
	}
	if info.IsDir() {
		return "offline", "sqlite database path is a directory"
	}
	if !info.Mode().IsRegular() {
		return "offline", "sqlite database path is not a regular file"
	}
	db, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		return "offline", err.Error()
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return "offline", err.Error()
	}
	return "active", "sqlite reachable"
}

func sqliteReadOnlyDSN(path string) string {
	endpoint := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	query := endpoint.Query()
	query.Set("mode", "ro")
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func checkWebAssetReachability(target string, timeout time.Duration) (string, string) {
	client := http.Client{Timeout: timeout}
	resp, err := requestWebAssetHealth(client, http.MethodHead, target)
	if err != nil {
		return "offline", err.Error()
	}
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		resp.Body.Close()
		resp, err = requestWebAssetHealth(client, http.MethodGet, target)
		if err != nil {
			return "offline", err.Error()
		}
	}
	defer resp.Body.Close()
	if resp.StatusCode >= http.StatusInternalServerError {
		return "offline", resp.Status
	}
	return "active", resp.Status
}

func requestWebAssetHealth(client http.Client, method, target string) (*http.Response, error) {
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func defaultProtocolPort(protocol model.Protocol) int {
	switch protocol {
	case model.ProtocolRDP:
		return 3389
	case model.ProtocolVNC:
		return 5900
	default:
		return 22
	}
}

func (s *Server) renewDueSelfSignedCertificates(task model.PlatformItem) (map[string]any, error) {
	items, err := s.cfg.Store.ListPlatformItems("certificates")
	if err != nil {
		return nil, err
	}
	renewBeforeDays := metadataIntDefault(task.Metadata["renew_before_days"], metadataIntDefault(task.Metadata["renewal_days"], 30))
	validityDays := metadataIntDefault(task.Metadata["validity_days"], 365)
	threshold := time.Now().UTC().Add(time.Duration(maxInt(renewBeforeDays, 0)) * 24 * time.Hour)
	renewed := 0
	skipped := 0
	results := []map[string]any{}
	for _, item := range items {
		if !strings.EqualFold(item.Type, "self-signed") {
			skipped++
			continue
		}
		if !certificateRenewalStatusAllowed(item) {
			skipped++
			continue
		}
		expiresAt, ok := metadataTime(item.Metadata["expires_at"])
		if ok && expiresAt.After(threshold) {
			skipped++
			continue
		}
		domain := firstMetadataString(item.Metadata, "domain", "common_name")
		if domain == "" {
			domain = item.Name
		}
		if strings.TrimSpace(domain) == "" {
			skipped++
			continue
		}
		certPEM, keyPEM, err := makeSelfSignedCertificate(certificateRequest{
			Domain: domain,
			DNS:    metadataStrings(item.Metadata["dns"]),
			IP:     metadataStrings(item.Metadata["ip"]),
			Days:   validityDays,
		})
		if err != nil {
			return nil, err
		}
		nextMetadata := map[string]any{}
		for key, value := range item.Metadata {
			nextMetadata[key] = value
		}
		nextExpiresAt := time.Now().UTC().Add(time.Duration(clampInt(validityDays, 1, 3650, 365)) * 24 * time.Hour)
		nextMetadata["domain"] = domain
		nextMetadata["certificate"] = string(certPEM)
		nextMetadata["private_key"] = string(keyPEM)
		nextMetadata["previous_expires_at"] = expiresAt
		nextMetadata["expires_at"] = nextExpiresAt
		nextMetadata["renewed_at"] = time.Now().UTC()
		_, err = s.cfg.Store.UpdatePlatformItem("certificates", item.ID, model.PlatformItemRequest{
			Status:   "issued",
			Metadata: nextMetadata,
		})
		if err != nil {
			return nil, err
		}
		renewed++
		results = append(results, map[string]any{"id": item.ID, "name": item.Name, "domain": domain, "expires_at": nextExpiresAt})
	}
	return map[string]any{
		"renewed_count": renewed,
		"skipped_count": skipped,
		"results":       results,
	}, nil
}

func certificateRenewalStatusAllowed(item model.PlatformItem) bool {
	switch strings.ToLower(strings.TrimSpace(item.Status)) {
	case "", "enabled", "active", "issued", "valid", "locked":
		return true
	default:
		return false
	}
}

func metadataIntDefault(value any, fallback int) int {
	if parsed, ok := metadataInt(value); ok {
		return parsed
	}
	return fallback
}

func maxInt(value, minimum int) int {
	if value < minimum {
		return minimum
	}
	return value
}
