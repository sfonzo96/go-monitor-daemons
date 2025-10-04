package host

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/sfonzo96/monitor-go/pkg/api"
	"github.com/sfonzo96/monitor-go/pkg/database"
)

type HostStatus struct {
	IP         string
	Alive      bool
	MACAddress string
}

func worker(ipChannel <-chan string, results chan<- HostStatus) {
	for ip := range ipChannel {
		status := isHostAlive(ip)
		results <- status
	}
}

func scanNetwork(network database.NetworkModel, knownHosts []database.HostModel) error {
	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%s", network.IPAddress, network.CIDRMask))
	if err != nil {
		return err
	}

	ones, _ := ipnet.Mask.Size()
	assignableIpsCount := int(math.Pow(2, float64(32-ones)) - 2)

	ipChannel := make(chan string, 1000)
	results := make(chan HostStatus, 1000)

	const numWorkers = 500 // Comment: starts 500 goroutines waiting for ips in order to check if host is alive
	for i := 0; i < numWorkers; i++ {
		go worker(ipChannel, results)
	}

	go func() {
		defer close(ipChannel)
		// Comment: Generate all possible assignable IPs in the subnet (count should match assignableIpsCount)
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			if !ip.Equal(ipnet.IP) && !isBroadcast(ip, ipnet) && ip.IsPrivate() {
				ipChannel <- ip.String()
			}
		}
	}()

	var checkedCount int

	db, err := database.NewMySQLDatabase(fmt.Sprintf("%s:%s@tcp(%s)/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_NAME"),
	))
	if err != nil {
		return err
	}
	defer db.Close()
	for checkedCount < assignableIpsCount {
		result := <-results
		checkedCount++

		dbHost, exists := isKnownHost(result.MACAddress, result.IP, knownHosts)
		if exists {
			db.UpdateHostStatus(*dbHost.ID, result.Alive)
		} else if result.Alive {
			client := api.NewClient(os.Getenv("API_BASE_URL"))
			newHost := api.NewHostRequest{
				IPAddress:  result.IP,
				MACAddress: result.MACAddress,
				NetworkID:  *network.ID,
				Hostname:   "unknown",
			}
			err := client.Post("/hosts", newHost)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func isKnownHost(macAddress, ipAddress string, knownHosts []database.HostModel) (*database.HostModel, bool) {
	for _, host := range knownHosts {
		if macAddress != "none" {
			if host.MACAddress == macAddress {
				return &host, true
			}
		} else if host.IPAddress == ipAddress {
			return &host, true
		}
	}
	return nil, false
}

// Comment: incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^ipnet.Mask[i]
	}
	return ip.Equal(broadcast)
}

func pingHost(ip string) bool {
	cmd := exec.Command("ping", "-c", "2", "-W", "2", ip)
	err := cmd.Run()
	return err == nil
}

func scanCommonTCPPorts(ip string, ports []int, timeout time.Duration) bool {
	for _, port := range ports {
		address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func scanCommonUDPPorts(ip string, ports []int, timeout time.Duration) bool {
	for _, port := range ports {
		address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("udp", address, timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

var localIPsAndMacs, _ = getLocalIpsAndMacs()

func isHostAlive(ip string) HostStatus {
	commonTCPPorts := []int{22, 53, 80, 135, 139, 443, 445, 1433, 3389, 5353, 5985, 8080, 9389}
	commonUDPPorts := []int{53, 67, 68, 123, 137, 161, 5353}
	status := HostStatus{IP: ip, Alive: false, MACAddress: "none"}

	if mac, isLocal := localIPsAndMacs[ip]; isLocal {
		status.Alive = true
		status.MACAddress = mac
		fmt.Println("Host alive detected as local interface:", ip, "MAC:", mac)
		return status
	}

	// Comment: Combining methods so IP is added to arp table
	pingHost(ip)
	scanCommonTCPPorts(ip, commonTCPPorts, 300*time.Millisecond)
	scanCommonUDPPorts(ip, commonUDPPorts, 300*time.Millisecond)

	if mac, ok := checkARPTable(ip); ok {
		status.Alive = true
		status.MACAddress = mac
	}

	return status
}

func checkARPTable(ip string) (string, bool) {
	cmd := exec.Command("arp", "-n", ip)
	output, err := cmd.Output()
	if err != nil {
		return "none", false
	}

	outputStr := string(output)
	// OK output example:
	// Dirección                TipoHW  DirecciónHW         Indic Máscara         Interfaz
	// 192.168.1.9              ether   08:00:27:0f:b6:d0   C                     enxf8e43b481329

	// No entry output example
	// 192.168.1.15 (192.168.1.15) -- no hay entradas
	// or
	// Dirección                TipoHW  DirecciónHW         Indic Máscara         Interfaz
	// 192.168.1.14                     (incompleto)                              enxf8e43b481329

	// Comment: Maybe not the most robust validation but works for now
	if strings.Contains(outputStr, "--") || strings.Contains(outputStr, "(incompleto)") {
		return "none", false
	}

	return extractMACFromARP(outputStr), strings.Contains(outputStr, ":") // Comment: ":"" Belongs to mac addresses so I'm assuming if there's a ":" a MAC address is present
}

func getLocalIpsAndMacs() (map[string]string, error) {
	localInterfaces := make(map[string]string)

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		if len(iface.HardwareAddr) == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		macAddr := iface.HardwareAddr.String()

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipv4 := ipNet.IP.To4(); ipv4 != nil && !ipv4.IsLoopback() {
				localInterfaces[ipv4.String()] = macAddr
			}
		}
	}

	return localInterfaces, nil
}

func extractMACFromARP(output string) string {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return "none"
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 3 {
		return "none"
	}

	return fields[2]
}

func ScanHosts(interval int) error {
	db, err := database.NewMySQLDatabase(fmt.Sprintf("%s:%s@tcp(%s)/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_NAME"),
	))
	if err != nil {
		return err
	}
	defer db.Close()

	for {
		networks, err := db.GetNetworks()
		if err != nil {
			return err
		}

		for _, network := range networks {
			networkCIDR := fmt.Sprintf("%s/%s", network.IPAddress, network.CIDRMask)

			_, ipnet, err := net.ParseCIDR(networkCIDR)
			if err != nil {
				fmt.Println("Failed to parse CIDR:", err)
				continue
			}

			if !ipnet.IP.IsPrivate() {
				continue
			}

			knownHosts, err := db.GetHostsByNetworkID(*network.ID)
			if err != nil {
				fmt.Println("Failed to get known hosts:", err)
				continue
			}

			err = scanNetwork(network, knownHosts)
			if err != nil {
				fmt.Println("Failed to scan network:", err)
				continue
			}
		}

		time.Sleep(time.Duration(interval) * time.Minute)
	}
}
