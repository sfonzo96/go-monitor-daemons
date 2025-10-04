package metrics

import (
	"fmt"
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/sfonzo96/monitor-go/pkg/api"
)

var metricsIds = map[string]int32{
	"cpu_usage":    1,
	"memory_usage": 2,
}

func CollectAndSendMetrics(interval int) error {
	client := api.NewClient(os.Getenv("API_BASE_URL"))

	for {
		cpuUsage, err := GetCpuUsage()
		if err != nil {
			return err
		}
		err = client.Post("/metrics", api.NewMetricRecordRequest{
			MetricId: int(metricsIds["cpu_usage"]),
			Value:    cpuUsage,
		})
		if err != nil {
			return err
		}

		memUsage, err := GetMemoryUsage()
		if err != nil {
			return err
		}

		err = client.Post("/metrics", api.NewMetricRecordRequest{
			MetricId: int(metricsIds["memory_usage"]),
			Value:    memUsage,
		})
		if err != nil {
			return err
		}

		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func GetCpuUsage() (float64, error) {
	cpuPercents, err := cpu.Percent(0, false)
	if err != nil {
		return 0, fmt.Errorf("failed to get CPU usage: %v", err)
	}
	if len(cpuPercents) > 0 {
		return cpuPercents[0], nil
	}
	return 0, fmt.Errorf("no CPU usage data available")
}

func GetMemoryUsage() (float64, error) {
	memStats, err := mem.VirtualMemory()
	if err != nil {
		return 0, fmt.Errorf("failed to get memory usage: %v", err)
	}

	return memStats.UsedPercent, nil
}
