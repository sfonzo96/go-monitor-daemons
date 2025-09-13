/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/port"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// portsCmd represents the ports command
var portsCmd = &cobra.Command{
	Use:   "ports",
	Short: "Lists open ports on a given host",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get IP from flag or config
		ip := viper.GetString("ip")

		if ip == "" {
			return fmt.Errorf("please provide an IP address using --ip/-ip flag")
		}

		ports, err := port.ScanPorts(ip, viper.GetString("range"))
		if err != nil {
			return err
		}

		for _, p := range ports {
			fmt.Printf("Port %d is open\n", p.Number)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(portsCmd)

	// Add flags
	portsCmd.Flags().StringP("ip", "i", "", "IP address or hostname to scan for open ports")
	portsCmd.Flags().StringP("range", "r", "1-1024", "Port range to scan for open ports")

	portsCmd.MarkFlagRequired("ip")

	// Bind the flag to viper
	viper.BindPFlag("ip", portsCmd.Flags().Lookup("ip"))
	viper.BindPFlag("range", portsCmd.Flags().Lookup("range"))

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// portsCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// portsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
