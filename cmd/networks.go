/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/sfonzo96/monitor-go/pkg/network"
	"github.com/spf13/cobra"
)

// networksCmd represents the networks command
var networksCmd = &cobra.Command{
	Use:   "networks",
	Short: "List networks the host is connected to",
	RunE: func(cmd *cobra.Command, args []string) error {
		nets, err := network.LookupLocalNetworks()
		if err != nil {
			return err
		}

		for _, n := range nets {
			fmt.Printf("Detected network: %s/%d\n", n.IPAddress, n.Mask)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(networksCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// networksCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// networksCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
