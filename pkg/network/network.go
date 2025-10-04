package network

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sfonzo96/monitor-go/pkg/api"
	"github.com/sfonzo96/monitor-go/pkg/database"
)

type Network struct {
	IPAddress   string    `json:"ipAddress"`
	Mask        int       `json:"CIDRMask"`
	Description string    `json:"description"`
	IpNet       net.IPNet `json:"-"`
}

func LookupLocalNetworks(interval int) error {
	client := api.NewClient(os.Getenv("API_BASE_URL"))

	db, err := database.NewMySQLDatabase(fmt.Sprintf("%s:%s@tcp(%s)/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_NAME"),
	))
	if err != nil {
		fmt.Println(err)
		return err
	}
	defer db.Close()

	for {
		networks := make([]Network, 0)
		seenNetworks := make(map[string]bool)

		ifaces, err := net.Interfaces()
		if err != nil {
			fmt.Println(err)
			return err
		}

		for _, iface := range ifaces {
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				ip, ipnet, _ := net.ParseCIDR(addr.String())
				if ip.To4() != nil && !ip.IsLoopback() {
					seenNetworks[ipnet.String()] = true

					mask, _ := strconv.Atoi(strings.Split(ipnet.String(), "/")[1])
					networkData := Network{
						IPAddress:   ipnet.IP.String(),
						Mask:        mask,
						IpNet:       *ipnet,
						Description: "No name",
					}

					networks = append(networks, networkData)
				}
			}
		}

		knownNetworks, err := db.GetNetworks()
		if err != nil {
			fmt.Println(err)
			return err
		}

		for _, network := range networks {
			if network.isKnown(knownNetworks) {
				continue
			}

			err := client.Post("/networks", api.NewNetworkRequest{IPAddress: network.IPAddress, CIDRMask: network.Mask, Description: network.Description})
			if err != nil {
				fmt.Println(err)
				return err
			}
		}

		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

func (net *Network) isKnown(knownNets []database.NetworkModel) bool {
	for _, dbNet := range knownNets {
		netCIDR := fmt.Sprintf("%s/%s", dbNet.IPAddress, dbNet.CIDRMask)
		if net.IpNet.String() == netCIDR {
			return true
		}
	}

	return false
}
