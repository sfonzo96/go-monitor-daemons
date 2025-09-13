package host

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/sfonzo96/monitor-go/pkg/api"
	"github.com/sfonzo96/monitor-go/pkg/database"
	"github.com/sfonzo96/monitor-go/pkg/network"
)

type Network struct {
	Id        int
	IPAddress string
	CIDRMask  int
}

// ScanConfig holds configuration for host scanning
type ScanConfig struct {
	Database   database.DatabaseInterface
	APIClient  *api.Client
	OutputFile string
}

type HostStatus struct {
	IP       string
	Alive    bool
	Method   string // "ping", "arp", "port scan" or "none"
	OpenPort int    // if detected via port scan
}

// Simplified worker function - just processes and sends results
func worker(ipChannel <-chan string, results chan<- HostStatus) {
	for ip := range ipChannel {
		status := isHostAlive(ip)
		results <- status
	}
}

// Much cleaner implementation using only channels
func scanNetwork(networkCIDR string) ([]HostStatus, error) {
	const numWorkers = 500

	_, ipnet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Calculate expected IP count for progress tracking
	ones, _ := ipnet.Mask.Size()
	expectedCount := 1<<uint(32-ones) - 2
	fmt.Printf("📊 Expected ~%d hosts to check in network %s\n", expectedCount, networkCIDR)

	// Create channels
	ipChannel := make(chan string, 1000)
	results := make(chan HostStatus, 1000)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go worker(ipChannel, results)
	}

	// Start IP generator
	go func() {
		defer close(ipChannel)
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			if !ip.Equal(ipnet.IP) && !isBroadcast(ip, ipnet) && ip.IsPrivate() {
				ipChannel <- ip.String()
			}
		}
	}()

	// Collect results with progress tracking
	var aliveHosts []HostStatus
	var aliveCount, checkedCount int

	for checkedCount < expectedCount {
		result := <-results
		checkedCount++

		if result.Alive {
			aliveCount++
			aliveHosts = append(aliveHosts, result)
			fmt.Printf("%s ALIVE ✅ (%s)\n", result.IP, result.Method)
		}

		// Progress update every 5000 checks
		if checkedCount%5000 == 0 {
			msg := fmt.Sprintf("📈 Progress: %d/%d checked, %d alive (%.1f%% complete)\n",
				checkedCount, expectedCount, aliveCount,
				float64(checkedCount)/float64(expectedCount)*100)
			fmt.Println(msg)
		}
	}

	return aliveHosts, nil
}

// incrementIP increments an IP address by 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// isBroadcast checks if IP is the broadcast address for the network
func isBroadcast(ip net.IP, ipnet *net.IPNet) bool {
	broadcast := make(net.IP, len(ip))
	for i := range ip {
		broadcast[i] = ip[i] | ^ipnet.Mask[i]
	}
	return ip.Equal(broadcast)
}

// pingHost attempts to ping a host using system ping command (faster timeout)
func pingHost(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	err := cmd.Run()
	return err == nil
}

func scanCommonPorts(ip string, ports []int, timeout time.Duration) (bool, int) {
	for _, port := range ports {
		address := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, timeout)
		if err == nil {
			conn.Close()
			return true, port
		}
	}
	return false, 0
}

// isHostAlive checks if a host is alive using multiple detection methods
func isHostAlive(ip string) HostStatus {
	status := HostStatus{IP: ip, Alive: false, Method: "none"}

	// Method 1: Try ping first (fastest and most reliable on Linux hosts)
	if pingHost(ip) {
		status.Alive = true
		status.Method = "ping"
		return status
	}

	// Method 2: Port scan on common ports (especially Windows ports) - If fails it should enable a detection on ARP check
	commonPorts := []int{22, 53, 80, 135, 139, 443, 445, 3389, 5353, 8080, 1433, 5985}
	if alive, port := scanCommonPorts(ip, commonPorts, 200*time.Millisecond); alive {
		status.Alive = true
		status.Method = "port scan"
		status.OpenPort = port
		return status
	}

	// Method 3: Check ARP table for recently contacted hosts
	if checkARPTable(ip) {
		status.Alive = true
		status.Method = "arp"
		return status
	}

	return status
}

// checkARPTable checks if the IP is in the ARP table (indicating recent network activity)
func checkARPTable(ip string) bool {
	cmd := exec.Command("arp", "-n", ip)
	output, err := cmd.Output()
	if err != nil {
		return false
	}

	outputStr := string(output)
	// OK output example
	// Dirección                TipoHW  DirecciónHW         Indic Máscara         Interfaz
	// 192.168.1.9              ether   08:00:27:0f:b6:d0   C                     enxf8e43b481329

	// No entry output example
	// 192.168.1.15 (192.168.1.15) -- no hay entradas

	// Maybe not the most robust validation but works for now
	if strings.Contains(outputStr, "--") {
		return false
	}

	return strings.Contains(outputStr, ":") // : Belongs to mac addresses so I'm assuming if there's a ":" a MAC address is present
}

func ScanHosts() ([]HostStatus, error) {
	return ScanHostsWithConfig(nil)
}

// ScanHostsWithConfig scans hosts with database integration
func ScanHostsWithConfig(config *ScanConfig) ([]HostStatus, error) {
	networks, err := network.LookupLocalNetworks()
	if err != nil {
		return nil, err
	}

	fmt.Printf("\n🔍 Total networks to scan: %d\n", len(networks))

	// Sort networks by size (bigger mask = less hosts)
	for i := 0; i < len(networks)-1; i++ {
		for j := i + 1; j < len(networks); j++ {
			if networks[i].Mask < networks[j].Mask {
				networks[i], networks[j] = networks[j], networks[i]
			}
		}
	}

	var allAliveHosts []HostStatus
	var knownHosts map[string]*database.Host

	// Load known hosts from database if config is provided
	if config != nil && config.Database != nil {
		knownHosts, err = loadKnownHosts(config.Database)
		if err != nil {
			fmt.Printf("⚠️ Warning: Could not load known hosts from database: %v\n", err)
			knownHosts = make(map[string]*database.Host)
		}

		// Check for new networks and post to API if configured
		err = processNewNetworks(networks, config)
		if err != nil {
			fmt.Printf("⚠️ Warning: Failed to process networks: %v\n", err)
		}
	} else {
		knownHosts = make(map[string]*database.Host)
	}

	// Process each network sequentially (smaller networks first)
	for _, network := range networks {
		// Create CIDR notation from IP and mask
		networkCIDR := fmt.Sprintf("%s/%d", network.IPAddress, network.Mask)
		fmt.Printf("\n🔍 Scanning network %s\n", networkCIDR)

		// Check if this is a private network range
		_, ipnet, err := net.ParseCIDR(networkCIDR)
		if err != nil {
			fmt.Printf("❌ Invalid CIDR %s: %v\n", networkCIDR, err)
			continue
		}

		if !ipnet.IP.IsPrivate() {
			fmt.Printf("⚠️  Skipping public network %s\n", networkCIDR)
			continue
		}

		// Use worker pool to scan the network
		aliveHosts, err := scanNetworkWithDatabase(networkCIDR, knownHosts, config)
		if err != nil {
			fmt.Printf("❌ Error scanning network %s: %v\n", networkCIDR, err)
			continue
		}

		// Add alive hosts from this network to the overall collection
		allAliveHosts = append(allAliveHosts, aliveHosts...)

		fmt.Printf("✅ Network %s scan complete: %d hosts alive\n\n", networkCIDR, len(aliveHosts))
	}
	fmt.Println("\n🎉 All network scans completed!")

	return allAliveHosts, nil
}

// loadKnownHosts loads all known hosts from the database into a map for quick lookup
func loadKnownHosts(db database.DatabaseInterface) (map[string]*database.Host, error) {
	hosts, err := db.GetHosts()
	if err != nil {
		return nil, err
	}

	knownHosts := make(map[string]*database.Host)
	for i := range hosts {
		knownHosts[hosts[i].IPAddress] = &hosts[i]
	}

	fmt.Printf("📊 Loaded %d known hosts from database\n", len(knownHosts))
	return knownHosts, nil
}

// processNewNetworks checks for new networks and posts them to API if configured
func processNewNetworks(localNetworks []network.Network, config *ScanConfig) error {
	if config == nil || config.Database == nil {
		return nil // No database configured
	}

	// Get known networks from database
	knownNetworks, err := config.Database.GetNetworks()
	if err != nil {
		return fmt.Errorf("failed to load known networks: %w", err)
	}

	// Create map for fast lookup
	knownNetworkMap := make(map[string]bool)
	for _, known := range knownNetworks {
		key := fmt.Sprintf("%s/%s", known.IPAddress, known.CIDRMask)
		knownNetworkMap[key] = true
	}

	// Check each local network
	for _, localNet := range localNetworks {
		networkCIDR := fmt.Sprintf("%s/%d", localNet.IPAddress, localNet.Mask)

		if !knownNetworkMap[networkCIDR] {
			// New network discovered
			fmt.Printf("🆕 New network discovered: %s\n", networkCIDR)

			// Post to API if configured
			if config.APIClient != nil {
				newNetwork := api.NewNetworkRequest{
					IPAddress:   localNet.IPAddress,
					CIDRMask:    fmt.Sprintf("/%d", localNet.Mask),
					Description: fmt.Sprintf("Auto-discovered network %s", networkCIDR),
					IsOnline:    true,
				}

				err = config.APIClient.PostNewNetwork(newNetwork)
				if err != nil {
					fmt.Printf("⚠️ Warning: Failed to post network %s to API: %v\n", networkCIDR, err)
				} else {
					fmt.Printf("📡 Posted new network %s to API\n", networkCIDR)
				}
			}
		}
	}

	return nil
}

// processHostStatus handles the database logic for host discovery as described in notes
func processHostStatus(status HostStatus, knownHosts map[string]*database.Host, config *ScanConfig) error {
	if config == nil || config.Database == nil {
		return nil // No database configured
	}

	knownHost, isKnown := knownHosts[status.IP]

	if isKnown {
		// Host is known
		if status.Alive {
			// If host is alive, check if dbstatus is true
			if !knownHost.IsOnline {
				// Change dbstatus to true
				err := config.Database.UpdateHostStatus(knownHost.ID, true, time.Now())
				if err != nil {
					return fmt.Errorf("failed to update host status to online: %w", err)
				}
				fmt.Printf("🔄 Updated host %s status to ONLINE\n", status.IP)
			} else {
				// Update last seen time
				err := config.Database.UpdateHostLastSeen(knownHost.ID, time.Now())
				if err != nil {
					return fmt.Errorf("failed to update host last seen: %w", err)
				}
			}
		} else {
			// Host is not alive, change dbstatus to false
			if knownHost.IsOnline {
				err := config.Database.UpdateHostStatus(knownHost.ID, false, time.Now())
				if err != nil {
					return fmt.Errorf("failed to update host status to offline: %w", err)
				}
				fmt.Printf("🔄 Updated host %s status to OFFLINE\n", status.IP)
			}
		}
	} else if status.Alive {
		// New host discovered and alive - POST to API if configured
		if config.APIClient != nil {
			newHost := api.NewHostRequest{
				IPAddress:  status.IP,
				MACAddress: "", // We might need to enhance this to get MAC from ARP
				NetworkID:  1,  // We might need to determine this based on the network
				Hostname:   "", // We might need to do reverse DNS lookup
				DetectedBy: status.Method,
				OpenPort:   status.OpenPort,
			}

			err := config.APIClient.PostNewHost(newHost)
			if err != nil {
				return fmt.Errorf("failed to post new host to API: %w", err)
			}
			fmt.Printf("📡 Posted new host %s to API (detected by %s)\n", status.IP, status.Method)
		}
	}

	return nil
}

// scanNetworkWithDatabase is an enhanced version of scanNetwork with database integration
func scanNetworkWithDatabase(networkCIDR string, knownHosts map[string]*database.Host, config *ScanConfig) ([]HostStatus, error) {
	const numWorkers = 500

	_, ipnet, err := net.ParseCIDR(networkCIDR)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %v", err)
	}

	// Calculate expected IP count for progress tracking
	ones, _ := ipnet.Mask.Size()
	expectedCount := 1<<uint(32-ones) - 2
	fmt.Printf("📊 Expected ~%d hosts to check in network %s\n", expectedCount, networkCIDR)

	// Create channels
	ipChannel := make(chan string, 1000)
	results := make(chan HostStatus, 1000)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go worker(ipChannel, results)
	}

	// Start IP generator
	go func() {
		defer close(ipChannel)
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
			if !ip.Equal(ipnet.IP) && !isBroadcast(ip, ipnet) && ip.IsPrivate() {
				ipChannel <- ip.String()
			}
		}
	}()

	// Collect results with progress tracking and database integration
	var aliveHosts []HostStatus
	var aliveCount, checkedCount int

	for checkedCount < expectedCount {
		result := <-results
		checkedCount++

		// Process host status with database logic
		if err := processHostStatus(result, knownHosts, config); err != nil {
			fmt.Printf("⚠️ Warning: Failed to process host %s: %v\n", result.IP, err)
		}

		if result.Alive {
			aliveCount++
			aliveHosts = append(aliveHosts, result)
			fmt.Printf("%s ALIVE ✅ (%s)\n", result.IP, result.Method)
		}

		// Progress update every 5000 checks
		if checkedCount%5000 == 0 {
			msg := fmt.Sprintf("📈 Progress: %d/%d checked, %d alive (%.1f%% complete)\n",
				checkedCount, expectedCount, aliveCount,
				float64(checkedCount)/float64(expectedCount)*100)
			fmt.Println(msg)
		}
	}

	return aliveHosts, nil
}
