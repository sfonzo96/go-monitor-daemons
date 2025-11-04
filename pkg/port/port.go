package port

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Port struct {
	Number int
	OK     bool
}

func worker(ip string, ports, results chan Port) {
	// Comment: Runs as an infinite for loop, stucks waiting for input from the ports channel
	for port := range ports {
		address := net.JoinHostPort(ip, strconv.Itoa(port.Number))
		conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err != nil {
			port.OK = false
			results <- port
			continue
		}

		conn.Close()
		port.OK = true
		results <- port
	}
}

func ScanPorts(ip, portRange string) ([]Port, error) {
	portExtremes := strings.Split(portRange, "-")
	minPort, err := strconv.Atoi(portExtremes[0])
	if err != nil {
		return nil, fmt.Errorf("invalid port range format")
	}
	maxPort, err := strconv.Atoi(portExtremes[1])
	if err != nil {
		return nil, fmt.Errorf("invalid port range format")
	}
	if minPort < 1 || maxPort > 65535 || minPort > maxPort {
		return nil, fmt.Errorf("port range must be between 1 and 65535 and min must be less than max")
	}

	maxWorkers := 100
	ports := make(chan Port, maxWorkers)
	results := make(chan Port, maxPort)
	var openPorts []Port

	// Comment: This creates a pool of go routines expecting the channel input, any of those can handle the port thus creating parallelism in order to speed up the process
	for range maxWorkers {
		go worker(ip, ports, results)
	}

	go func() {
		defer close(ports)
		for i := minPort; i <= maxPort; i++ {
			ports <- Port{Number: i}
		}
	}()

	for i := minPort; i <= maxPort; i++ {
		port := <-results // Comment: Blocks execution until a worker sends a value to results channel
		if port.OK {
			openPorts = append(openPorts, port)
		}
	}

	close(results)

	if len(openPorts) < 1 {
		// fmt.Println("No open ports found")
		return nil, nil
	}

	return openPorts, nil
}
