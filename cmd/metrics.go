/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/metrics"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Collects data on system performance and resource usage",
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, _ := cmd.Flags().GetInt32("interval")

		if interval == 0 || interval < 0 {
			return fmt.Errorf("please provide a valid interval using --interval/-i flag")
		}

		err := metrics.CollectAndSendMetrics(int(interval))
		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(metricsCmd)

	metricsCmd.Flags().Int32P("interval", "i", 5, "Interval in seconds to collect metrics")

	viper.BindPFlag("interval", metricsCmd.Flags().Lookup("interval"))
}
