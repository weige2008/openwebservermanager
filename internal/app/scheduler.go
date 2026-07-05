package app

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"openwebservermanager/internal/model"
)

const defaultSchedulerPollInterval = 30 * time.Second

type SchedulerConfig struct {
	PollInterval time.Duration
	Logger       *slog.Logger
}

type TaskScheduler struct {
	server       *Server
	pollInterval time.Duration
	logger       *slog.Logger
	ctx          context.Context
	cancel       context.CancelFunc
	done         chan struct{}

	mu      sync.Mutex
	running map[string]bool
}

func (s *Server) StartScheduler(ctx context.Context, cfg SchedulerConfig) *TaskScheduler {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaultSchedulerPollInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	schedulerCtx, cancel := context.WithCancel(ctx)
	scheduler := &TaskScheduler{
		server:       s,
		pollInterval: cfg.PollInterval,
		logger:       cfg.Logger,
		ctx:          schedulerCtx,
		cancel:       cancel,
		done:         make(chan struct{}),
		running:      map[string]bool{},
	}
	go scheduler.run()
	return scheduler
}

func (s *TaskScheduler) Stop() {
	s.cancel()
	<-s.done
}

func (s *TaskScheduler) run() {
	defer close(s.done)
	s.scan()
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.scan()
		}
	}
}

func (s *TaskScheduler) scan() {
	tasks, err := s.server.cfg.Store.ListPlatformItems("scheduled_tasks")
	if err != nil {
		s.logger.Warn("scheduled task scan failed", "error", err)
		return
	}
	now := time.Now().UTC()
	for _, task := range tasks {
		if !scheduledTaskEnabled(task) {
			continue
		}
		due, next, shouldPersistNext := scheduledTaskDue(task, now)
		if shouldPersistNext {
			s.persistNextRun(task, next)
		}
		if due {
			s.runTask(task)
		}
	}
}

func (s *TaskScheduler) persistNextRun(task model.PlatformItem, next time.Time) {
	metadata := cloneMetadata(task.Metadata)
	metadata["next_run_at"] = next.Format(time.RFC3339Nano)
	if _, err := s.server.cfg.Store.UpdatePlatformItem("scheduled_tasks", task.ID, model.PlatformItemRequest{Metadata: metadata}); err != nil {
		s.logger.Warn("scheduled task next run update failed", "task_id", task.ID, "error", err)
	}
}

func (s *TaskScheduler) runTask(task model.PlatformItem) {
	s.mu.Lock()
	if s.running[task.ID] {
		s.mu.Unlock()
		return
	}
	s.running[task.ID] = true
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.running, task.ID)
			s.mu.Unlock()
		}()
		if _, err := s.server.executeScheduledTask(nil, task, "scheduled"); err != nil {
			s.logger.Warn("scheduled task run failed", "task_id", task.ID, "task", task.Name, "error", err)
		}
	}()
}

func scheduledTaskEnabled(task model.PlatformItem) bool {
	status := strings.ToLower(strings.TrimSpace(task.Status))
	return status == "" || status == "enabled" || status == "active"
}

func scheduledTaskDue(task model.PlatformItem, now time.Time) (bool, time.Time, bool) {
	now = now.UTC()
	if next, ok := metadataTime(task.Metadata["next_run_at"]); ok {
		return !next.After(now), next.UTC(), false
	}
	if runOnStart, ok := metadataBoolValue(task.Metadata["run_on_start"]); ok && runOnStart {
		if _, alreadyRan := metadataTime(task.Metadata["last_run_at"]); alreadyRan {
			return false, time.Time{}, false
		}
		return true, now, false
	}
	next, ok := nextScheduledTaskRunAfter(task, now)
	if !ok {
		return false, time.Time{}, false
	}
	return !next.After(now), next, true
}

func nextScheduledTaskRunAfter(task model.PlatformItem, after time.Time) (time.Time, bool) {
	after = after.UTC()
	if interval, ok := scheduledTaskInterval(task.Metadata); ok {
		return after.Add(interval).UTC(), true
	}
	cron := firstMetadataString(task.Metadata, "cron", "cron_expression", "cronExpression")
	if cron == "" {
		return time.Time{}, false
	}
	next, ok := nextCronRun(cron, after)
	return next.UTC(), ok
}

func scheduledTaskInterval(metadata map[string]any) (time.Duration, bool) {
	for _, key := range []string{"interval_ms", "run_every_ms", "every_ms"} {
		if value, ok := metadataInt(metadata[key]); ok && value > 0 {
			return time.Duration(value) * time.Millisecond, true
		}
	}
	for _, key := range []string{"interval_seconds", "run_every_seconds", "every_seconds"} {
		if value, ok := metadataInt(metadata[key]); ok && value > 0 {
			return time.Duration(value) * time.Second, true
		}
	}
	for _, key := range []string{"interval_minutes", "run_every_minutes", "every_minutes"} {
		if value, ok := metadataInt(metadata[key]); ok && value > 0 {
			return time.Duration(value) * time.Minute, true
		}
	}
	if raw := firstMetadataString(metadata, "interval", "run_every", "every"); raw != "" {
		if duration, err := time.ParseDuration(raw); err == nil && duration > 0 {
			return duration, true
		}
		if seconds, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil && seconds > 0 {
			return time.Duration(seconds) * time.Second, true
		}
	}
	return 0, false
}

func nextCronRun(expr string, after time.Time) (time.Time, bool) {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 6 {
		return time.Time{}, false
	}
	second, ok := cronSingleValue(fields[0], 0, 59)
	if !ok {
		return time.Time{}, false
	}
	minutes, ok := cronValues(fields[1], 0, 59)
	if !ok || len(minutes) == 0 {
		return time.Time{}, false
	}
	hours, ok := cronValues(fields[2], 0, 23)
	if !ok || len(hours) == 0 {
		return time.Time{}, false
	}
	start := after.UTC().Add(time.Second)
	deadline := start.AddDate(1, 0, 0)
	for candidate := time.Date(start.Year(), start.Month(), start.Day(), start.Hour(), start.Minute(), second, 0, time.UTC); candidate.Before(deadline); candidate = candidate.Add(time.Minute) {
		if !candidate.After(after) {
			continue
		}
		if !containsInt(hours, candidate.Hour()) || !containsInt(minutes, candidate.Minute()) {
			continue
		}
		return candidate, true
	}
	return time.Time{}, false
}

func cronSingleValue(field string, min, max int) (int, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(field))
	if err != nil || value < min || value > max {
		return 0, false
	}
	return value, true
}

func cronValues(field string, min, max int) ([]int, bool) {
	field = strings.TrimSpace(field)
	if field == "*" || field == "?" {
		values := make([]int, 0, max-min+1)
		for value := min; value <= max; value++ {
			values = append(values, value)
		}
		return values, true
	}
	result := []int{}
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		switch {
		case strings.Contains(part, "/"):
			pieces := strings.Split(part, "/")
			if len(pieces) != 2 {
				return nil, false
			}
			step, err := strconv.Atoi(strings.TrimSpace(pieces[1]))
			if err != nil || step <= 0 {
				return nil, false
			}
			start := min
			if base := strings.TrimSpace(pieces[0]); base != "*" && base != "?" {
				parsed, err := strconv.Atoi(base)
				if err != nil || parsed < min || parsed > max {
					return nil, false
				}
				start = parsed
			}
			for value := start; value <= max; value += step {
				result = append(result, value)
			}
		case strings.Contains(part, "-"):
			pieces := strings.Split(part, "-")
			if len(pieces) != 2 {
				return nil, false
			}
			start, err := strconv.Atoi(strings.TrimSpace(pieces[0]))
			if err != nil {
				return nil, false
			}
			end, err := strconv.Atoi(strings.TrimSpace(pieces[1]))
			if err != nil || start < min || end > max || start > end {
				return nil, false
			}
			for value := start; value <= end; value++ {
				result = append(result, value)
			}
		default:
			value, err := strconv.Atoi(part)
			if err != nil || value < min || value > max {
				return nil, false
			}
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return nil, false
	}
	return uniqueSortedInts(result), true
}

func uniqueSortedInts(values []int) []int {
	seen := map[int]bool{}
	result := []int{}
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		result = append(result, value)
	}
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j] < result[i] {
				result[i], result[j] = result[j], result[i]
			}
		}
	}
	return result
}

func containsInt(values []int, needle int) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
