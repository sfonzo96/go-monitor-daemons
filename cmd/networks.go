package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/network"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var networksCmd = &cobra.Command{
	Use:   "networks",
	Short: "List networks the host is connected to",
	RunE: func(cmd *cobra.Command, args []string) error {
		interval, _ := cmd.Flags().GetInt32("interval")

		if interval == 0 || interval < 0 {
			return fmt.Errorf("please provide a valid interval using --interval/-i flag")
		}

		err := network.LookupLocalNetworks(int(interval))
		if err != nil {
			fmt.Println(err)
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(networksCmd)

	networksCmd.Flags().Int32P("interval", "i", 1, "Interval in minutes to lookup networks")

	viper.BindPFlag("interval", networksCmd.Flags().Lookup("interval"))
}
