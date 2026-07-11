package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"
)

const (
	recordingTranscodeQueued     = "queued"
	recordingTranscodeProcessing = "processing"
	recordingTranscodeCompleted  = "completed"
	recordingTranscodeFailed     = "failed"
)

type RecordingTranscodeResult struct {
	Path     string
	MimeType string
}

type RecordingTranscoder interface {
	Available() (bool, string)
	Transcode(context.Context, string, string) (RecordingTranscodeResult, error)
}

type guacencTranscoder struct {
	guacencPath string
	ffmpegPath  string
	timeout     time.Duration
}

func newGuacencTranscoderFromEnvironment() RecordingTranscoder {
	guacencPath := strings.TrimSpace(os.Getenv("OPENWEBSERVERMANAGER_GUACENC_PATH"))
	if guacencPath == "" {
		guacencPath = "guacenc"
	}
	ffmpegPath := strings.TrimSpace(os.Getenv("OPENWEBSERVERMANAGER_FFMPEG_PATH"))
	if ffmpegPath == "" {
		ffmpegPath = "ffmpeg"
	}
	timeout := 30 * time.Minute
	if raw := strings.TrimSpace(os.Getenv("OPENWEBSERVERMANAGER_RECORDING_TRANSCODE_TIMEOUT_SECONDS")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil && seconds > 0 {
			timeout = time.Duration(seconds) * time.Second
		}
	}
	return &guacencTranscoder{guacencPath: guacencPath, ffmpegPath: ffmpegPath, timeout: timeout}
}

func (t *guacencTranscoder) Available() (bool, string) {
	guacencPath, err := exec.LookPath(t.guacencPath)
	if err != nil {
		return false, "guacenc executable not found"
	}
	ffmpegPath, err := exec.LookPath(t.ffmpegPath)
	if err != nil {
		return false, "ffmpeg executable not found"
	}
	return true, "guacenc=" + guacencPath + " ffmpeg=" + ffmpegPath
}

func (t *guacencTranscoder) Transcode(ctx context.Context, sourcePath, outputDir string) (RecordingTranscodeResult, error) {
	guacencPath, err := exec.LookPath(t.guacencPath)
	if err != nil {
		return RecordingTranscodeResult{}, errors.New("guacenc executable not found")
	}
	ffmpegPath, err := exec.LookPath(t.ffmpegPath)
	if err != nil {
		return RecordingTranscodeResult{}, errors.New("ffmpeg executable not found")
	}
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	generatedPath := sourcePath + ".m4v"
	finalPath := filepath.Join(outputDir, "recording-video.mp4")
	if err := ensureChildPath(outputDir, generatedPath); err != nil {
		return RecordingTranscodeResult{}, err
	}
	if err := ensureChildPath(outputDir, finalPath); err != nil {
		return RecordingTranscodeResult{}, err
	}
	_ = os.Remove(generatedPath)
	_ = os.Remove(finalPath)
	output, err := exec.CommandContext(ctx, guacencPath, "-f", sourcePath).CombinedOutput()
	if err != nil {
		_ = os.Remove(generatedPath)
		detail := strings.TrimSpace(string(output))
		if len(detail) > 2048 {
			detail = detail[len(detail)-2048:]
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return RecordingTranscodeResult{}, errors.New("recording transcode timed out")
		}
		if detail == "" {
			return RecordingTranscodeResult{}, fmt.Errorf("guacenc failed: %w", err)
		}
		return RecordingTranscodeResult{}, fmt.Errorf("guacenc failed: %w: %s", err, detail)
	}
	defer os.Remove(generatedPath)
	output, err = exec.CommandContext(ctx, ffmpegPath,
		"-hide_banner", "-loglevel", "error", "-y", "-i", generatedPath,
		"-an", "-c:v", "libx264", "-preset", "veryfast", "-pix_fmt", "yuv420p",
		"-movflags", "+faststart", finalPath,
	).CombinedOutput()
	if err != nil {
		_ = os.Remove(finalPath)
		detail := strings.TrimSpace(string(output))
		if len(detail) > 2048 {
			detail = detail[len(detail)-2048:]
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return RecordingTranscodeResult{}, errors.New("recording transcode timed out")
		}
		if detail == "" {
			return RecordingTranscodeResult{}, fmt.Errorf("ffmpeg failed: %w", err)
		}
		return RecordingTranscodeResult{}, fmt.Errorf("ffmpeg failed: %w: %s", err, detail)
	}
	return RecordingTranscodeResult{Path: finalPath, MimeType: "video/mp4"}, nil
}

type recordingTranscodeRegistry struct {
	mu     sync.Mutex
	active map[string]struct{}
}

func (r *recordingTranscodeRegistry) start(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active == nil {
		r.active = map[string]struct{}{}
	}
	if _, exists := r.active[id]; exists {
		return false
	}
	r.active[id] = struct{}{}
	return true
}

func (r *recordingTranscodeRegistry) finish(id string) {
	r.mu.Lock()
	delete(r.active, id)
	r.mu.Unlock()
}

func (r *recordingTranscodeRegistry) running(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, exists := r.active[id]
	return exists
}

type recordingTranscodeStatus struct {
	Available  bool       `json:"available"`
	Detail     string     `json:"detail,omitempty"`
	Status     string     `json:"status,omitempty"`
	Error      string     `json:"error,omitempty"`
	VideoSize  int64      `json:"video_size,omitempty"`
	VideoURL   string     `json:"video_url,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (s *Server) handleAuditRecordingTranscode(w http.ResponseWriter, r *http.Request, id string) {
	recording, ok := s.auditRecordingTarget(w, r, id)
	if !ok {
		return
	}
	item, exists, err := s.cfg.Store.GetPlatformItem("offline_sessions", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !exists {
		writeError(w, http.StatusNotFound, "offline session not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.recordingTranscodeStatus(id, item))
	case http.MethodPost:
		s.startAuditRecordingTranscode(w, r, id, recording, item)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) startAuditRecordingTranscode(w http.ResponseWriter, r *http.Request, id string, recording auditRecording, item model.PlatformItem) {
	available, detail := s.recordingTranscoder.Available()
	if !available {
		writeError(w, http.StatusServiceUnavailable, detail)
		return
	}
	file, info, err := recordingPlaybackFile(recording.path, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "playable recording not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sourcePath := file.Name()
	_ = file.Close()
	if !s.recordingTranscodes.start(id) {
		writeError(w, http.StatusConflict, "recording transcode already running")
		return
	}
	ownerID := s.currentUserID(r)
	if err := s.createRecordingOperationLog(r, "audit.recording.transcode", recordingTranscodeQueued, id, recording.protocol, "queued offline session recording transcode", map[string]any{
		"recording_file": filepath.Base(info.Name()),
		"recording_size": info.Size(),
	}); err != nil {
		s.recordingTranscodes.finish(id)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	queuedAt := time.Now().UTC()
	updated, err := s.updateRecordingTranscodeMetadata(id, func(metadata map[string]any) {
		metadata["recording_transcode_status"] = recordingTranscodeQueued
		metadata["recording_transcode_queued_at"] = queuedAt
		metadata["recording_transcode_started_at"] = nil
		metadata["recording_transcode_finished_at"] = nil
		metadata["recording_transcode_error"] = ""
	})
	if err != nil {
		s.recordingTranscodes.finish(id)
		writeError(w, http.StatusInternalServerError, s.recordingStatePersistError(r, id, recording.protocol, "persist recording transcode queue state failed", err).Error())
		return
	}
	go s.runRecordingTranscode(id, sourcePath, ownerID, recording.protocol)
	_ = s.audit(r, "audit.recording.transcode", id, recording.protocol, "queued offline session recording transcode")
	writeJSON(w, http.StatusAccepted, s.recordingTranscodeStatus(id, updated))
}

func (s *Server) handleAuditRecordingVideo(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	recording, ok := s.auditRecordingTarget(w, r, id)
	if !ok {
		return
	}
	item, exists, err := s.cfg.Store.GetPlatformItem("offline_sessions", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !exists || firstMetadataString(item.Metadata, "recording_transcode_status") != recordingTranscodeCompleted {
		writeError(w, http.StatusNotFound, "transcoded recording not found")
		return
	}
	name := filepath.Base(firstMetadataString(item.Metadata, "recording_video_file"))
	if name == "." || name == "" || name != firstMetadataString(item.Metadata, "recording_video_file") {
		writeError(w, http.StatusBadRequest, "transcoded recording path is invalid")
		return
	}
	file, info, err := openRegularRecordingFile(filepath.Join(recording.path, name))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeError(w, http.StatusNotFound, "transcoded recording not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer file.Close()
	if err := s.createRecordingOperationLog(r, "audit.recording.video.playback", "success", id, recording.protocol, "opened transcoded recording playback", map[string]any{
		"recording_file": name,
		"recording_size": info.Size(),
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	mimeType := firstMetadataString(item.Metadata, "recording_video_mime_type")
	if mimeType == "" {
		mimeType = "video/mp4"
	}
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", "inline; filename=\""+id+filepath.Ext(name)+"\"")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func (s *Server) recordingTranscodeStatus(id string, item model.PlatformItem) recordingTranscodeStatus {
	available, detail := s.recordingTranscoder.Available()
	status := firstMetadataString(item.Metadata, "recording_transcode_status")
	running := s.recordingTranscodes.running(id)
	if running {
		status = recordingTranscodeProcessing
	} else if status == recordingTranscodeQueued || status == recordingTranscodeProcessing {
		status = recordingTranscodeFailed
		if firstMetadataString(item.Metadata, "recording_transcode_error") == "" {
			item.Metadata["recording_transcode_error"] = "transcode task is no longer running"
		}
	}
	result := recordingTranscodeStatus{
		Available: available,
		Detail:    detail,
		Status:    status,
		Error:     firstMetadataString(item.Metadata, "recording_transcode_error"),
		VideoSize: metadataInt64Value(item.Metadata["recording_video_size"]),
	}
	videoName := firstMetadataString(item.Metadata, "recording_video_file")
	if videoName != "" && status == recordingTranscodeCompleted {
		recordingPath, pathErr := s.recordingDirectory(firstMetadataString(item.Metadata, "recording_path"))
		var file *os.File
		var info os.FileInfo
		var fileErr error
		if pathErr == nil && filepath.Base(videoName) == videoName {
			file, info, fileErr = openRegularRecordingFile(filepath.Join(recordingPath, videoName))
		} else {
			fileErr = errStorageSpecialFile
		}
		if fileErr == nil {
			_ = file.Close()
			result.VideoSize = info.Size()
			result.VideoURL = "/api/admin/audit/offline-sessions/" + id + "/recording/video"
		} else {
			if file != nil {
				_ = file.Close()
			}
			result.Status = recordingTranscodeFailed
			result.Error = "transcoded recording file is missing or invalid"
		}
	}
	result.StartedAt = metadataTimePointer(item.Metadata["recording_transcode_started_at"])
	result.FinishedAt = metadataTimePointer(item.Metadata["recording_transcode_finished_at"])
	return result
}

func metadataInt64Value(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return parsed
	case string:
		parsed, _ := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return parsed
	default:
		return 0
	}
}

func metadataTimePointer(value any) *time.Time {
	var parsed time.Time
	switch typed := value.(type) {
	case time.Time:
		parsed = typed
	case string:
		parsed, _ = time.Parse(time.RFC3339Nano, typed)
	}
	if parsed.IsZero() {
		return nil
	}
	parsed = parsed.UTC()
	return &parsed
}

func (s *Server) updateRecordingTranscodeMetadata(id string, update func(map[string]any)) (model.PlatformItem, error) {
	item, ok, err := s.cfg.Store.GetPlatformItem("offline_sessions", id)
	if err != nil {
		return model.PlatformItem{}, err
	}
	if !ok {
		return model.PlatformItem{}, os.ErrNotExist
	}
	item.Metadata = cloneMetadata(item.Metadata)
	update(item.Metadata)
	return s.cfg.Store.SavePlatformItem("offline_sessions", item)
}

func (s *Server) runRecordingTranscode(id, sourcePath, ownerID string, protocol model.Protocol) {
	defer s.recordingTranscodes.finish(id)
	startedAt := time.Now().UTC()
	_, err := s.updateRecordingTranscodeMetadata(id, func(metadata map[string]any) {
		metadata["recording_transcode_status"] = recordingTranscodeProcessing
		metadata["recording_transcode_started_at"] = startedAt
		metadata["recording_transcode_finished_at"] = nil
		metadata["recording_transcode_error"] = ""
	})
	if err != nil {
		s.writeRecordingTranscodeLog(id, ownerID, protocol, recordingTranscodeFailed, "failed to persist recording transcode start", err)
		return
	}
	recordingDir := filepath.Dir(sourcePath)
	result, transcodeErr := s.recordingTranscoder.Transcode(context.Background(), sourcePath, recordingDir)
	finishedAt := time.Now().UTC()
	if transcodeErr != nil {
		_, persistErr := s.updateRecordingTranscodeMetadata(id, func(metadata map[string]any) {
			metadata["recording_transcode_status"] = recordingTranscodeFailed
			metadata["recording_transcode_finished_at"] = finishedAt
			metadata["recording_transcode_error"] = transcodeErr.Error()
		})
		if persistErr != nil {
			transcodeErr = fmt.Errorf("%w; additionally failed to persist transcode failure: %v", transcodeErr, persistErr)
		}
		s.writeRecordingTranscodeLog(id, ownerID, protocol, recordingTranscodeFailed, "recording transcode failed", transcodeErr)
		return
	}
	file, info, err := openRegularRecordingFile(result.Path)
	if err == nil {
		_ = file.Close()
	}
	if err != nil || filepath.Dir(result.Path) != recordingDir {
		if err == nil {
			err = errors.New("transcoded recording escaped recording directory")
		}
		_, _ = s.updateRecordingTranscodeMetadata(id, func(metadata map[string]any) {
			metadata["recording_transcode_status"] = recordingTranscodeFailed
			metadata["recording_transcode_finished_at"] = finishedAt
			metadata["recording_transcode_error"] = err.Error()
		})
		s.writeRecordingTranscodeLog(id, ownerID, protocol, recordingTranscodeFailed, "recording transcode output invalid", err)
		return
	}
	_, err = s.updateRecordingTranscodeMetadata(id, func(metadata map[string]any) {
		metadata["recording_transcode_status"] = recordingTranscodeCompleted
		metadata["recording_transcode_finished_at"] = finishedAt
		metadata["recording_transcode_error"] = ""
		metadata["recording_video_file"] = filepath.Base(result.Path)
		metadata["recording_video_mime_type"] = result.MimeType
		metadata["recording_video_size"] = info.Size()
	})
	if err != nil {
		s.writeRecordingTranscodeLog(id, ownerID, protocol, recordingTranscodeFailed, "failed to persist recording transcode completion", err)
		return
	}
	s.writeRecordingTranscodeLog(id, ownerID, protocol, recordingTranscodeCompleted, "recording transcode completed", nil)
}

func (s *Server) writeRecordingTranscodeLog(id, ownerID string, protocol model.Protocol, status, description string, transcodeErr error) {
	metadata := map[string]any{"session_id": id}
	if transcodeErr != nil {
		metadata["error"] = transcodeErr.Error()
	}
	_, err := s.cfg.Store.CreatePlatformItem("operation_logs", model.PlatformItemRequest{
		Name: "audit.recording.transcode", Type: "recording", Status: status, Protocol: protocol,
		TargetID: id, OwnerID: ownerID, Description: description, Metadata: metadata,
	})
	if err != nil {
		_ = s.cfg.Store.Audit(model.AuditLog{
			UserID: ownerID, Action: "operation.log.persist_failed", TargetID: id, Protocol: protocol,
			Detail: "persist recording transcode operation log failed: " + err.Error(),
		})
	}
}

func (s *Server) reconcileInterruptedRecordingTranscodes() {
	items, err := s.cfg.Store.ListPlatformItems("offline_sessions")
	if err != nil {
		return
	}
	for _, item := range items {
		status := firstMetadataString(item.Metadata, "recording_transcode_status")
		if status != recordingTranscodeQueued && status != recordingTranscodeProcessing {
			continue
		}
		item.Metadata = cloneMetadata(item.Metadata)
		item.Metadata["recording_transcode_status"] = recordingTranscodeFailed
		item.Metadata["recording_transcode_error"] = "transcode interrupted by service restart"
		item.Metadata["recording_transcode_finished_at"] = time.Now().UTC()
		_, _ = s.cfg.Store.SavePlatformItem("offline_sessions", item)
	}
}
