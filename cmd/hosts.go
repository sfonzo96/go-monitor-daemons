package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/host"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var hostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "List hosts connected to visible networks",
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, _ := cmd.Flags().GetInt32("interval")

		if interval == 0 || interval < 0 {
			return fmt.Errorf("please provide a valid interval using --interval/-i flag")
		}

		err := host.ScanHosts(int(interval))
		return err
	},
}

func init() {
	rootCmd.AddCommand(hostsCmd)

	hostsCmd.Flags().Int32P("interval", "i", 1, "Interval in minutes to lookup hosts")

	viper.BindPFlag("interval", hostsCmd.Flags().Lookup("interval"))
}
