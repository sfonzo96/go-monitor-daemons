package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sfonzo96/monitor-go/pkg/host"
)

// ScanReport represents the complete scan report
type ScanReport struct {
	Timestamp   time.Time         `json:"timestamp"`
	TotalHosts  int               `json:"total_hosts"`
	AliveHosts  int               `json:"alive_hosts"`
	ScanResults []host.HostStatus `json:"scan_results"`
	Summary     map[string]int    `json:"summary"` // Method -> count
}

// GenerateReport creates a scan report from host status results
func GenerateReport(hosts []host.HostStatus) *ScanReport {
	report := &ScanReport{
		Timestamp:   time.Now(),
		TotalHosts:  len(hosts),
		ScanResults: hosts,
		Summary:     make(map[string]int),
	}

	// Count alive hosts and methods
	for _, h := range hosts {
		if h.Alive {
			report.AliveHosts++
			report.Summary[h.Method]++
		}
	}

	return report
}

// WriteToFile writes the report to a file in the specified format
func (r *ScanReport) WriteToFile(filename string) error {
	ext := strings.ToLower(filename[strings.LastIndex(filename, ".")+1:])

	var content []byte
	var err error

	switch ext {
	case "json":
		content, err = r.ToJSON()
	case "txt", "out":
		content = []byte(r.ToText())
	case "csv":
		content = []byte(r.ToCSV())
	default:
		content = []byte(r.ToText()) // Default to text format
	}

	if err != nil {
		return fmt.Errorf("failed to generate report content: %w", err)
	}

	err = os.WriteFile(filename, content, 0644)
	if err != nil {
		return fmt.Errorf("failed to write report to file %s: %w", filename, err)
	}

	fmt.Printf("📄 Report saved to: %s\n", filename)
	return nil
}

// ToJSON converts the report to JSON format
func (r *ScanReport) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToText converts the report to human-readable text format
func (r *ScanReport) ToText() string {
	var sb strings.Builder

	sb.WriteString("=== NETWORK SCAN REPORT ===\n")
	sb.WriteString(fmt.Sprintf("Scan Time: %s\n", r.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Total Hosts Scanned: %d\n", r.TotalHosts))
	sb.WriteString(fmt.Sprintf("Alive Hosts: %d\n", r.AliveHosts))
	sb.WriteString("\n=== DETECTION METHODS SUMMARY ===\n")

	for method, count := range r.Summary {
		sb.WriteString(fmt.Sprintf("%-12s: %d hosts\n", strings.Title(method), count))
	}

	sb.WriteString("\n=== ALIVE HOSTS DETAILS ===\n")
	for _, host := range r.ScanResults {
		if host.Alive {
			line := fmt.Sprintf("%-15s | %-10s", host.IP, host.Method)
			if host.OpenPort > 0 {
				line += fmt.Sprintf(" | Port: %d", host.OpenPort)
			}
			sb.WriteString(line + "\n")
		}
	}

	return sb.String()
}

// ToCSV converts the report to CSV format
func (r *ScanReport) ToCSV() string {
	var sb strings.Builder

	// Header
	sb.WriteString("IP Address,Status,Detection Method,Open Port\n")

	// Data rows
	for _, host := range r.ScanResults {
		status := "Offline"
		if host.Alive {
			status = "Online"
		}

		openPort := ""
		if host.OpenPort > 0 {
			openPort = fmt.Sprintf("%d", host.OpenPort)
		}

		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s\n", host.IP, status, host.Method, openPort))
	}

	return sb.String()
}

// PrintToStdout prints the report to standard output in text format
func (r *ScanReport) PrintToStdout() {
	fmt.Print(r.ToText())
}
