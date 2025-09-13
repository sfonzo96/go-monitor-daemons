package network

import (
	"net"
	"strconv"
	"strings"
)

type Network struct {
	IPAddress string    `json:"ipAddress"`
	Mask      int       `json:"CIDRMask"`
	IpNet     net.IPNet `json:"-"`
}

func LookupLocalNetworks() ([]Network, error) {
	networks := make([]Network, 0)
	seenNetworks := make(map[string]bool)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, ipnet, _ := net.ParseCIDR(addr.String())
			if ip.To4() != nil && !ip.IsLoopback() {
				netKey := ipnet.String()

				if seenNetworks[netKey] {
					continue
				}
				seenNetworks[netKey] = true
				mask, _ := strconv.Atoi(strings.Split(ipnet.String(), "/")[1])
				networkData := Network{
					IPAddress: ipnet.IP.String(),
					Mask:      mask,
					IpNet:     *ipnet,
				}

				networks = append(networks, networkData)
			}
		}
	}
	return networks, nil
}
