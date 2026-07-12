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
	if err := s.server.dispatchEmailNotifications(now); err != nil {
		s.logger.Warn("email notification dispatch failed", "error", err)
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
	switch len(fields) {
	case 5:
		fields = append([]string{"0"}, fields...)
	case 6:
	default:
		return time.Time{}, false
	}
	seconds, ok := cronValues(fields[0], 0, 59)
	if !ok || len(seconds) == 0 {
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
	daysOfMonth, dayOfMonthWildcard, ok := cronValuesWithWildcard(fields[3], 1, 31)
	if !ok || len(daysOfMonth) == 0 {
		return time.Time{}, false
	}
	months, _, ok := cronValuesWithWildcardAliases(fields[4], 1, 12, cronMonthAliases())
	if !ok || len(months) == 0 {
		return time.Time{}, false
	}
	daysOfWeek, dayOfWeekWildcard, ok := cronDayOfWeekValues(fields[5])
	if !ok || len(daysOfWeek) == 0 {
		return time.Time{}, false
	}
	start := after.UTC().Add(time.Second)
	deadline := start.AddDate(1, 0, 0)
	for candidateMinute := time.Date(start.Year(), start.Month(), start.Day(), start.Hour(), start.Minute(), 0, 0, time.UTC); candidateMinute.Before(deadline); candidateMinute = candidateMinute.Add(time.Minute) {
		if !containsInt(hours, candidateMinute.Hour()) || !containsInt(minutes, candidateMinute.Minute()) {
			continue
		}
		if !cronDateMatches(candidateMinute, daysOfMonth, dayOfMonthWildcard, months, daysOfWeek, dayOfWeekWildcard) {
			continue
		}
		for _, second := range seconds {
			candidate := time.Date(candidateMinute.Year(), candidateMinute.Month(), candidateMinute.Day(), candidateMinute.Hour(), candidateMinute.Minute(), second, 0, time.UTC)
			if !candidate.After(after) {
				continue
			}
			return candidate, true
		}
	}
	return time.Time{}, false
}

func cronValues(field string, min, max int) ([]int, bool) {
	values, _, ok := cronValuesWithWildcard(field, min, max)
	return values, ok
}

func cronValuesWithWildcard(field string, min, max int) ([]int, bool, bool) {
	return cronValuesWithWildcardAliases(field, min, max, nil)
}

func cronValuesWithWildcardAliases(field string, min, max int, aliases map[string]int) ([]int, bool, bool) {
	field = strings.ToUpper(strings.TrimSpace(field))
	if field == "*" || field == "?" {
		values := make([]int, 0, max-min+1)
		for value := min; value <= max; value++ {
			values = append(values, value)
		}
		return values, true, true
	}
	result := []int{}
	for _, part := range strings.Split(field, ",") {
		values, ok := cronPartValues(part, min, max, aliases)
		if !ok {
			return nil, false, false
		}
		result = append(result, values...)
	}
	if len(result) == 0 {
		return nil, false, false
	}
	return uniqueSortedInts(result), false, true
}

func cronPartValues(part string, min, max int, aliases map[string]int) ([]int, bool) {
	part = strings.ToUpper(strings.TrimSpace(part))
	if part == "" {
		return nil, false
	}
	base := part
	step := 1
	hasStep := false
	if before, after, cutHasStep := strings.Cut(part, "/"); cutHasStep {
		base = strings.TrimSpace(before)
		parsedStep, err := strconv.Atoi(strings.TrimSpace(after))
		if err != nil || parsedStep <= 0 {
			return nil, false
		}
		step = parsedStep
		hasStep = true
	}
	start, end, ok := cronPartRange(base, min, max, aliases)
	if !ok {
		return nil, false
	}
	if hasStep && base != "*" && base != "?" && !strings.Contains(base, "-") {
		end = max
	}
	values := []int{}
	for value := start; value <= end; value += step {
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, false
	}
	return values, true
}

func cronPartRange(base string, min, max int, aliases map[string]int) (int, int, bool) {
	base = strings.ToUpper(strings.TrimSpace(base))
	if base == "*" || base == "?" {
		return min, max, true
	}
	if strings.Contains(base, "-") {
		pieces := strings.Split(base, "-")
		if len(pieces) != 2 {
			return 0, 0, false
		}
		start, ok := cronFieldValue(pieces[0], min, max, aliases)
		if !ok {
			return 0, 0, false
		}
		end, ok := cronFieldValue(pieces[1], min, max, aliases)
		if !ok || start > end {
			return 0, 0, false
		}
		return start, end, true
	}
	value, ok := cronFieldValue(base, min, max, aliases)
	if !ok {
		return 0, 0, false
	}
	return value, value, true
}

func cronFieldValue(value string, min, max int, aliases map[string]int) (int, bool) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if aliases != nil {
		if parsed, ok := aliases[value]; ok {
			return parsed, parsed >= min && parsed <= max
		}
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < min || parsed > max {
		return 0, false
	}
	return parsed, true
}

func cronDayOfWeekValues(field string) ([]int, bool, bool) {
	values, wildcard, ok := cronValuesWithWildcardAliases(field, 0, 7, cronDayOfWeekAliases())
	if !ok {
		return nil, false, false
	}
	for index, value := range values {
		if value == 7 {
			values[index] = 0
		}
	}
	return uniqueSortedInts(values), wildcard, true
}

func cronMonthAliases() map[string]int {
	return map[string]int{
		"JAN": 1,
		"FEB": 2,
		"MAR": 3,
		"APR": 4,
		"MAY": 5,
		"JUN": 6,
		"JUL": 7,
		"AUG": 8,
		"SEP": 9,
		"OCT": 10,
		"NOV": 11,
		"DEC": 12,
	}
}

func cronDayOfWeekAliases() map[string]int {
	return map[string]int{
		"SUN": 0,
		"MON": 1,
		"TUE": 2,
		"WED": 3,
		"THU": 4,
		"FRI": 5,
		"SAT": 6,
	}
}

func cronDateMatches(candidate time.Time, daysOfMonth []int, dayOfMonthWildcard bool, months []int, daysOfWeek []int, dayOfWeekWildcard bool) bool {
	if !containsInt(months, int(candidate.Month())) {
		return false
	}
	dayOfMonthMatches := containsInt(daysOfMonth, candidate.Day())
	dayOfWeekMatches := containsInt(daysOfWeek, int(candidate.Weekday()))
	if !dayOfMonthWildcard && !dayOfWeekWildcard {
		return dayOfMonthMatches || dayOfWeekMatches
	}
	if !dayOfMonthWildcard && !dayOfMonthMatches {
		return false
	}
	if !dayOfWeekWildcard && !dayOfWeekMatches {
		return false
	}
	return true
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
