/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/api"
	"github.com/sfonzo96/monitor-go/pkg/database"
	"github.com/sfonzo96/monitor-go/pkg/host"
	"github.com/sfonzo96/monitor-go/pkg/report"
	"github.com/spf13/cobra"
)

// hostsCmd represents the hosts command
var hostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "List hosts connected to visible networks",
	Long: `Scan and list hosts connected to visible networks. 
Supports database integration to track known hosts and API notifications for new discoveries.

Examples:
  monitor-go hosts                                    # Basic scan with stdout output
  monitor-go hosts --output report.json             # Save scan results to JSON file
  monitor-go hosts --output report.txt              # Save scan results to text file  
  monitor-go hosts --output report.csv              # Save scan results to CSV file
  monitor-go hosts --db-dsn "user:pass@tcp(localhost:3306)/monitor" # Use database
  monitor-go hosts --api-url https://api.example.com --api-key secret # Use API`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get flag values
		outputFile, _ := cmd.Flags().GetString("output")
		dbDSN, _ := cmd.Flags().GetString("db-dsn")
		apiURL, _ := cmd.Flags().GetString("api-url")
		apiKey, _ := cmd.Flags().GetString("api-key")

		// Initialize scan configuration
		var config *host.ScanConfig
		if dbDSN != "" || apiURL != "" {
			config = &host.ScanConfig{
				OutputFile: outputFile,
			}

			// Initialize database connection if DSN provided
			if dbDSN != "" {
				db, err := database.NewMySQLDatabase(dbDSN)
				if err != nil {
					return fmt.Errorf("failed to connect to database: %w", err)
				}
				defer db.Close()
				config.Database = db
				fmt.Println("✅ Connected to database")
			}

			// Initialize API client if URL provided
			if apiURL != "" {
				config.APIClient = api.NewClient(apiURL, apiKey)
				fmt.Println("✅ API client configured")
			}
		}

		// Perform the scan
		var hosts []host.HostStatus
		var err error

		if config != nil {
			hosts, err = host.ScanHostsWithConfig(config)
		} else {
			hosts, err = host.ScanHosts()
		}

		if err != nil {
			return err
		}

		// Generate report
		scanReport := report.GenerateReport(hosts)

		// Output results
		if outputFile != "" {
			// Save to file
			err = scanReport.WriteToFile(outputFile)
			if err != nil {
				return fmt.Errorf("failed to write report: %w", err)
			}
		} else {
			// Print to stdout in the original format for backward compatibility
			for _, h := range hosts {
				fmt.Printf("Host: %s, Alive: %t, Method: %s, Open Port: %d\n", h.IP, h.Alive, h.Method, h.OpenPort)
			}

			// Print summary
			fmt.Printf("\n=== SCAN SUMMARY ===\n")
			fmt.Printf("Total hosts checked: %d\n", scanReport.TotalHosts)
			fmt.Printf("Alive hosts found: %d\n", scanReport.AliveHosts)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(hostsCmd)

	// Output flags
	hostsCmd.Flags().StringP("output", "o", "", "Output file for scan results (supports .json, .txt, .csv formats)")

	// Database flags
	hostsCmd.Flags().String("db-dsn", "", "Database DSN for tracking known hosts (e.g., 'user:pass@tcp(localhost:3306)/monitor')")

	// API flags
	hostsCmd.Flags().String("api-url", "", "API base URL for posting new host discoveries")
	hostsCmd.Flags().String("api-key", "", "API key for authentication")
}
