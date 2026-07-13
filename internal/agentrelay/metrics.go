package agentrelay

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/host"
	"github.com/shirou/gopsutil/v4/mem"
	gnet "github.com/shirou/gopsutil/v4/net"
)

type HostMetrics struct {
	CPUPercent       float64
	MemoryUsedBytes  int64
	MemoryTotalBytes int64
	DiskUsedBytes    int64
	DiskTotalBytes   int64
	NetworkRXBytes   int64
	NetworkTXBytes   int64
	Details          map[string]any
}

type MetricsCollector func(context.Context) (HostMetrics, error)

func CollectHostMetrics(ctx context.Context) (HostMetrics, error) {
	metrics := HostMetrics{Details: map[string]any{
		"collected_at": time.Now().UTC(),
		"collector":    "gopsutil",
		"goos":         runtime.GOOS,
		"goarch":       runtime.GOARCH,
	}}
	errs := []error{}

	percentages, err := cpu.PercentWithContext(ctx, 100*time.Millisecond, false)
	if err != nil {
		errs = append(errs, err)
	} else if len(percentages) > 0 {
		metrics.CPUPercent = clampMetricPercent(percentages[0])
	}
	if count, countErr := cpu.CountsWithContext(ctx, true); countErr == nil && count > 0 {
		metrics.Details["cpu_logical_count"] = count
	}

	memory, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		errs = append(errs, err)
	} else {
		metrics.MemoryUsedBytes = metricInt64(memory.Used)
		metrics.MemoryTotalBytes = metricInt64(memory.Total)
	}

	diskPath, err := os.Getwd()
	if err != nil {
		diskPath = "."
	}
	usage, err := disk.UsageWithContext(ctx, diskPath)
	if err != nil {
		errs = append(errs, err)
	} else {
		metrics.DiskUsedBytes = metricInt64(usage.Used)
		metrics.DiskTotalBytes = metricInt64(usage.Total)
		metrics.Details["disk_path"] = diskPath
	}

	counters, err := gnet.IOCountersWithContext(ctx, false)
	if err != nil {
		errs = append(errs, err)
	} else {
		var received uint64
		var sent uint64
		for _, counter := range counters {
			received = saturatingMetricAdd(received, counter.BytesRecv)
			sent = saturatingMetricAdd(sent, counter.BytesSent)
		}
		metrics.NetworkRXBytes = metricInt64(received)
		metrics.NetworkTXBytes = metricInt64(sent)
	}

	if uptime, uptimeErr := host.UptimeWithContext(ctx); uptimeErr == nil {
		metrics.Details["uptime_seconds"] = uptime
	}
	if joined := errors.Join(errs...); joined != nil {
		metrics.Details["collection_error"] = joined.Error()
		return metrics, joined
	}
	return metrics, nil
}

func clampMetricPercent(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func metricInt64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func saturatingMetricAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}
