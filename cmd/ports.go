package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/port"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Lists open ports on a given host",
	RunE: func(cmd *cobra.Command, args []string) error {
		ip := viper.GetString("ip")

		if ip == "" {
			return fmt.Errorf("please provide an IP address using --ip/-ip flag")
		}

		ports, err := port.ScanPorts(ip, viper.GetString("range"))
		if err != nil {
			return err
		}

		for _, p := range ports {
			fmt.Printf("%d  ", p.Number)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(portsCmd)

	portsCmd.Flags().StringP("ip", "i", "", "IP address or hostname to scan for open ports")
	portsCmd.Flags().StringP("range", "r", "1-1024", "Port range to scan for open ports")

	portsCmd.MarkFlagRequired("ip")

	viper.BindPFlag("ip", portsCmd.Flags().Lookup("ip"))
	viper.BindPFlag("range", portsCmd.Flags().Lookup("range"))
}
