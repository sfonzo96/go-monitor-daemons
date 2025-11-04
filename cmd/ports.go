package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/host"
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

		// Is online:
		if !host.PingHost(ip) {
			fmt.Println("Host is offline or unreachable:", ip)
			return nil
		}
		ports, err := port.ScanPorts(ip, viper.GetString("range"))
		if err != nil {
			return err
		}

		if ports == nil {
			fmt.Println("No open ports found for", ip)
			return nil
		}
		fmt.Println("Open ports for", ip, ":")
		for _, p := range ports {
			fmt.Println("-", p.Number)
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
