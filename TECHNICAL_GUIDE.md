# Monitor-Go: Complete Technical Documentation

## Table of Contents
1. [Application Overview](#application-overview)
2. [Project Structure](#project-structure)
3. [Core Go Concepts Used](#core-go-concepts-used)
4. [Detailed Package Analysis](#detailed-package-analysis)
5. [Application Flow](#application-flow)
6. [Database Integration](#database-integration)
7. [API Integration](#api-integration)
8. [Concurrency and Performance](#concurrency-and-performance)
9. [Error Handling](#error-handling)
10. [Future Modifications Guide](#future-modifications-guide)

---

## Application Overview

**Monitor-Go** is a network scanning tool that discovers hosts on local networks. It can:
- Scan networks to find active hosts
- Track known hosts in a database
- Send notifications for new host discoveries via API
- Generate reports in multiple formats (JSON, TXT, CSV)
- Run as a background service for continuous monitoring

### Key Features
- **Multi-method host detection**: ping, ARP table lookup, TCP port scanning
- **Concurrent scanning**: Uses Go goroutines for parallel processing
- **Database persistence**: MySQL integration for host tracking
- **API integration**: HTTP client for external notifications
- **Flexible output**: Multiple report formats

---

## Project Structure

```
monitor-go/
├── main.go                 # Application entry point
├── go.mod                  # Go module definition
├── go.sum                  # Dependency checksums
├── cmd/                    # Command definitions (Cobra CLI)
│   ├── root.go            # Root command setup
│   ├── hosts.go           # Hosts scanning command
│   ├── networks.go        # Network commands  
│   └── ports.go           # Port scanning commands
├── pkg/                    # Application packages
│   ├── host/              # Host scanning logic
│   │   └── host.go
│   ├── network/           # Network discovery
│   │   └── network.go
│   ├── port/              # Port scanning
│   │   └── port.go
│   ├── database/          # Database operations
│   │   ├── models.go      # Data structures
│   │   └── database.go    # MySQL implementation
│   ├── api/               # HTTP API client
│   │   └── client.go
│   └── report/            # Report generation
│       └── report.go
├── CONFIG.md              # Configuration examples
└── notes.md               # Development notes
```

---

## Core Go Concepts Used

### 1. **Packages and Modules**
```go
// Package declaration - every Go file starts with this
package main

// Import statements - bringing in external functionality
import (
    "fmt"                    // Standard library for formatting
    "net"                    // Network operations
    "database/sql"           // SQL database interface
    _ "github.com/go-sql-driver/mysql"  // MySQL driver (blank import)
)
```

**Key Points:**
- `package main` creates an executable program
- `package <name>` creates a reusable library
- Imports can be from standard library or external modules
- Blank import (`_`) imports for side effects only (driver registration)

### 2. **Interfaces**
```go
// Interface definition - a contract that types must fulfill
type DatabaseInterface interface {
    GetHosts() ([]Host, error)
    CreateHost(host *Host) error
    Close() error
}

// Implementation - any type with these methods satisfies the interface
type MySQLDatabase struct {
    db *sql.DB
}

func (m *MySQLDatabase) GetHosts() ([]Host, error) {
    // Implementation here
}
```

**Why interfaces matter:**
- Enable polymorphism (different implementations, same interface)
- Make testing easier (mock implementations)
- Reduce coupling between components

### 3. **Structs and Methods**
```go
// Struct definition - groups related data
type Host struct {
    ID          int       `json:"id" db:"id"`           // Field tags for JSON/DB mapping
    IPAddress   string    `json:"ip_address" db:"ip_address"`
    IsOnline    bool      `json:"is_online" db:"is_online"`
    FirstSeen   time.Time `json:"first_seen" db:"first_seen"`
}

// Method with receiver - functions that belong to a type
func (h *Host) IsExpired() bool {
    return time.Since(h.FirstSeen) > 30*24*time.Hour
}
```

**Field Tags Explained:**
- `json:"ip_address"` - How this field appears in JSON
- `db:"ip_address"` - How this field maps to database columns

### 4. **Channels and Goroutines**
```go
// Channel creation - for communication between goroutines
ipChannel := make(chan string, 1000)    // Buffered channel
results := make(chan HostStatus, 1000)  // Another buffered channel

// Goroutine - concurrent function execution
go worker(ipChannel, results)  // Starts function in background

// Channel operations
ipChannel <- "192.168.1.1"     // Send to channel
result := <-results            // Receive from channel
close(ipChannel)               // Close channel (no more sends)
```

### 5. **Error Handling**
```go
// Go's explicit error handling pattern
result, err := someFunction()
if err != nil {
    return fmt.Errorf("operation failed: %w", err)  // Wrap error with context
}

// Error wrapping preserves original error while adding context
```

---

## Detailed Package Analysis

### 1. **main.go - Application Entry Point**
```go
package main

import "github.com/sfonzo96/monitor-go/cmd"

func main() {
    cmd.Execute()  // Delegates to Cobra CLI framework
}
```

**What happens here:**
- Go looks for `func main()` in `package main` as the entry point
- We delegate immediately to the Cobra command framework
- This keeps main.go minimal and testable

### 2. **cmd/hosts.go - Command Line Interface**

#### Cobra Framework Usage
```go
var hostsCmd = &cobra.Command{
    Use:   "hosts",                    // Command name
    Short: "List hosts connected...",  // Brief description  
    Long:  `Detailed description...`,  // Full help text
    RunE: func(cmd *cobra.Command, args []string) error {
        // Command execution logic
    },
}
```

#### Flag Handling
```go
// Flag definition in init()
hostsCmd.Flags().StringP("output", "o", "", "Output file...")

// Flag retrieval in RunE
outputFile, _ := cmd.Flags().GetString("output")
```

**Cobra Benefits:**
- Automatic help generation
- Flag parsing and validation
- Subcommand organization
- Shell completion support

#### Configuration Pattern
```go
var config *host.ScanConfig
if dbDSN != "" || apiURL != "" {
    config = &host.ScanConfig{
        OutputFile: outputFile,
    }
    
    if dbDSN != "" {
        db, err := database.NewMySQLDatabase(dbDSN)
        if err != nil {
            return fmt.Errorf("failed to connect: %w", err)
        }
        defer db.Close()  // Ensures cleanup when function exits
        config.Database = db
    }
}
```

**Key Patterns:**
- Configuration object pattern for optional features
- `defer` for resource cleanup
- Early return on errors

### 3. **pkg/database/ - Database Layer**

#### models.go - Data Structures
```go
type Host struct {
    ID          int       `json:"id" db:"id"`
    MACAddress  string    `json:"mac_address" db:"mac_address"`
    IPAddress   string    `json:"ip_address" db:"ip_address"`
    NetworkID   int       `json:"network_id" db:"network_id"`
    Hostname    string    `json:"hostname" db:"hostname"`
    FirstSeen   time.Time `json:"first_seen" db:"first_seen"`
    LastSeen    time.Time `json:"last_seen" db:"last_seen"`
    IsOnline    bool      `json:"is_online" db:"is_online"`
}
```

**Design Decisions:**
- Struct tags for JSON serialization and database mapping
- Standard Go naming (PascalCase for exported fields)
- `time.Time` for timestamp handling
- `bool` for simple status flags

#### database.go - Implementation

##### Interface Definition
```go
type DatabaseInterface interface {
    // Network operations
    GetNetworks() ([]Network, error)
    CreateNetwork(network *Network) error
    
    // Host operations  
    GetHosts() ([]Host, error)
    GetHostByIP(ipAddress string) (*Host, error)
    CreateHost(host *Host) error
    UpdateHostStatus(id int, isOnline bool, lastSeen time.Time) error
    
    // Connection management
    Close() error
    Ping() error
}
```

**Interface Benefits:**
- Testability (can mock database)
- Swappable implementations (MySQL, PostgreSQL, etc.)
- Clear contract definition

##### MySQL Implementation
```go
type MySQLDatabase struct {
    db *sql.DB  // Pointer to sql.DB from standard library
}

func NewMySQLDatabase(dsn string) (*MySQLDatabase, error) {
    db, err := sql.Open("mysql", dsn)  // Open connection
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    if err := db.Ping(); err != nil {  // Test connection
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    return &MySQLDatabase{db: db}, nil
}
```

**Connection Management:**
- `sql.Open()` creates a connection pool, not a single connection
- `Ping()` verifies the connection actually works
- Error wrapping with `fmt.Errorf` and `%w` verb

##### CRUD Operations Example
```go
func (m *MySQLDatabase) GetHostByIP(ipAddress string) (*Host, error) {
    query := "SELECT id, mac_address, ip_address, network_id, hostname, first_seen, last_seen, is_online FROM host WHERE ip_address = ?"
    row := m.db.QueryRow(query, ipAddress)
    
    var host Host
    err := row.Scan(&host.ID, &host.MACAddress, &host.IPAddress, &host.NetworkID, 
                   &host.Hostname, &host.FirstSeen, &host.LastSeen, &host.IsOnline)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil  // Not found, but not an error
        }
        return nil, err
    }
    
    return &host, nil
}
```

**SQL Best Practices:**
- Parameterized queries (`?`) prevent SQL injection
- `QueryRow` for single results, `Query` for multiple
- `Scan` maps columns to struct fields
- Special handling for `sql.ErrNoRows`

### 4. **pkg/api/ - HTTP Client**

#### Client Structure
```go
type Client struct {
    baseURL    string
    httpClient *http.Client
    apiKey     string
}

func NewClient(baseURL, apiKey string) *Client {
    return &Client{
        baseURL: baseURL,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,  // Prevent hanging requests
        },
        apiKey: apiKey,
    }
}
```

#### HTTP Request Pattern
```go
func (c *Client) PostNewHost(host NewHostRequest) error {
    jsonData, err := json.Marshal(host)  // Convert struct to JSON
    if err != nil {
        return fmt.Errorf("failed to marshal JSON: %w", err)
    }
    
    url := c.baseURL + "/api/hosts"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    
    req.Header.Set("Content-Type", "application/json")
    if c.apiKey != "" {
        req.Header.Set("Authorization", "Bearer "+c.apiKey)
    }
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send request: %w", err)
    }
    defer resp.Body.Close()  // Always close response body
    
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("API request failed with status %d", resp.StatusCode)
    }
    
    return nil
}
```

**HTTP Client Patterns:**
- Configured timeout prevents hanging
- JSON marshaling for request bodies
- Header management for authentication
- Status code validation
- Resource cleanup with `defer`

### 5. **pkg/host/ - Core Scanning Logic**

#### Concurrency Architecture
```go
func scanNetwork(networkCIDR string) ([]HostStatus, error) {
    const numWorkers = 500  // Number of concurrent scanners
    
    // Create channels for communication
    ipChannel := make(chan string, 1000)      // IPs to scan
    results := make(chan HostStatus, 1000)    // Scan results
    
    // Start worker goroutines
    for i := 0; i < numWorkers; i++ {
        go worker(ipChannel, results)  // Each worker runs concurrently
    }
    
    // Generate IPs to scan
    go func() {
        defer close(ipChannel)  // Signal no more IPs coming
        for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
            if !ip.Equal(ipnet.IP) && !isBroadcast(ip, ipnet) && ip.IsPrivate() {
                ipChannel <- ip.String()  // Send IP to workers
            }
        }
    }()
    
    // Collect results
    var aliveHosts []HostStatus
    for checkedCount < expectedCount {
        result := <-results  // Receive result from any worker
        if result.Alive {
            aliveHosts = append(aliveHosts, result)
        }
    }
    
    return aliveHosts, nil
}
```

**Concurrency Patterns:**
- **Worker Pool**: Fixed number of workers process jobs from a queue
- **Producer-Consumer**: One goroutine generates work, others consume it
- **Buffered Channels**: Prevent blocking when sending/receiving

#### Worker Function
```go
func worker(ipChannel <-chan string, results chan<- HostStatus) {
    for ip := range ipChannel {  // Range over channel until closed
        status := isHostAlive(ip)
        results <- status
    }
}
```

**Channel Direction:**
- `<-chan string` - receive-only channel
- `chan<- HostStatus` - send-only channel
- Prevents accidental misuse of channels

#### Host Detection Methods
```go
func isHostAlive(ip string) HostStatus {
    status := HostStatus{IP: ip, Alive: false, Method: "none"}
    
    // Method 1: ICMP Ping
    if pingHost(ip) {
        status.Alive = true
        status.Method = "ping"
        return status
    }
    
    // Method 2: TCP Port Scan
    if alive, port := scanCommonPorts(ip, commonPorts, 200*time.Millisecond); alive {
        status.Alive = true
        status.Method = "port scan"
        status.OpenPort = port
        return status
    }
    
    // Method 3: ARP Table Check
    if checkARPTable(ip) {
        status.Alive = true
        status.Method = "arp"
        return status
    }
    
    return status
}
```

**Detection Strategy:**
- Try fastest method first (ping)
- Fallback to TCP ports for firewalled hosts
- Check ARP table for recently contacted hosts
- Early return on first success

#### Database Integration Logic
```go
func processHostStatus(status HostStatus, knownHosts map[string]*database.Host, config *ScanConfig) error {
    knownHost, isKnown := knownHosts[status.IP]
    
    if isKnown {
        // Host exists in database
        if status.Alive {
            if !knownHost.IsOnline {
                // Host came back online
                err := config.Database.UpdateHostStatus(knownHost.ID, true, time.Now())
                // Handle error...
            } else {
                // Host still online, update last seen
                err := config.Database.UpdateHostLastSeen(knownHost.ID, time.Now())
                // Handle error...
            }
        } else {
            // Host went offline
            if knownHost.IsOnline {
                err := config.Database.UpdateHostStatus(knownHost.ID, false, time.Now())
                // Handle error...
            }
        }
    } else if status.Alive {
        // New host discovered
        if config.APIClient != nil {
            newHost := api.NewHostRequest{
                IPAddress:  status.IP,
                DetectedBy: status.Method,
                OpenPort:   status.OpenPort,
            }
            err := config.APIClient.PostNewHost(newHost)
            // Handle error...
        }
    }
    
    return nil
}
```

**Business Logic Implementation:**
- Map lookup for O(1) known host checking
- Conditional database updates based on state changes
- API notifications for new discoveries only
- Comprehensive error handling

#### Network Discovery Logic
```go
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
            // New network discovered - POST to API
            if config.APIClient != nil {
                newNetwork := api.NewNetworkRequest{
                    IPAddress:   localNet.IPAddress,
                    CIDRMask:    fmt.Sprintf("/%d", localNet.Mask),
                    Description: fmt.Sprintf("Auto-discovered network %s", networkCIDR),
                    IsOnline:    true,
                }
                
                err = config.APIClient.PostNewNetwork(newNetwork)
                // Handle error...
            }
        }
    }

    return nil
}
```

**Network Discovery Features:**
- Automatic detection of local network interfaces
- Database lookup to identify new networks
- API integration for new network notifications
- CIDR notation handling for network identification

### 6. **pkg/report/ - Report Generation**

#### Report Structure
```go
type ScanReport struct {
    Timestamp   time.Time             `json:"timestamp"`
    TotalHosts  int                   `json:"total_hosts"`
    AliveHosts  int                   `json:"alive_hosts"`
    ScanResults []host.HostStatus     `json:"scan_results"`
    Summary     map[string]int        `json:"summary"`
}
```

#### Format-Specific Output
```go
func (r *ScanReport) WriteToFile(filename string) error {
    ext := strings.ToLower(filename[strings.LastIndex(filename, ".")+1:])
    
    var content []byte
    var err error
    
    switch ext {
    case "json":
        content, err = r.ToJSON()
    case "txt", "out":
        content = []byte(r.ToText())
    case "csv":
        content = []byte(r.ToCSV())
    default:
        content = []byte(r.ToText())
    }
    
    if err != nil {
        return fmt.Errorf("failed to generate content: %w", err)
    }
    
    err = os.WriteFile(filename, content, 0644)
    if err != nil {
        return fmt.Errorf("failed to write file: %w", err)
    }
    
    return nil
}
```

**File Format Detection:**
- Extract extension from filename
- Switch statement for different formats
- Default fallback to text format

---

## Application Flow

### 1. **Startup Sequence**
```
main() 
  └── cmd.Execute()
      └── cobra.Command.Execute()
          └── hostsCmd.RunE()
```

### 2. **Command Execution Flow**
```
hostsCmd.RunE()
├── Parse command line flags
├── Initialize configuration (database, API)
├── Call host.ScanHostsWithConfig() or host.ScanHosts()
├── Generate report from results
└── Output to file or stdout
```

### 3. **Scanning Process**
```
ScanHostsWithConfig()
├── Load known hosts from database
├── Load known networks from database
├── Process network discoveries (POST new networks to API)
├── Discover local networks
├── For each network:
│   ├── Create worker pool (500 goroutines)
│   ├── Generate IP addresses
│   ├── Distribute work via channels
│   ├── Collect results
│   └── Process host status with business logic
└── Return all alive hosts
```

### 4. **Business Logic Flow**
```
processHostStatus()
├── Check if host is known in database
├── If KNOWN host:
│   ├── Host alive + was offline → Update DB to online
│   ├── Host alive + was online → Update last_seen timestamp
│   └── Host offline + was online → Update DB to offline
├── If UNKNOWN host + alive:
│   └── POST to API for business logic processing
└── Log all status changes

processNewNetworks()
├── Get known networks from database
├── For each discovered local network:
│   ├── Check if network exists in database
│   └── If new network → POST to API
```

### 5. **Concurrent Scanning Detail**
```
scanNetworkWithDatabase()
├── Create channels (ipChannel, results)
├── Start 500 worker goroutines
├── Start IP generator goroutine
├── Main thread collects results:
│   ├── Receive from results channel
│   ├── Process host status with business logic
│   ├── Update progress
│   └── Continue until all IPs checked
└── Return alive hosts
```

---

## Database Integration

### 1. **Schema Design**
```sql
-- Networks table
CREATE TABLE networks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),      -- Network IP (e.g., "192.168.1.0")
    cidr_mask VARCHAR(45),       -- CIDR notation (e.g., "/24")
    description VARCHAR(50),     -- Human-readable description
    is_online BOOLEAN,           -- Whether we're connected to this network
    UNIQUE KEY uniq_network (ip_address, cidr_mask)
);

-- Hosts table
CREATE TABLE host (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(255),    -- MAC address (if available)
    ip_address VARCHAR(45) NOT NULL,  -- Host IP address
    network_id INT NOT NULL,     -- Foreign key to networks
    hostname VARCHAR(255),       -- Resolved hostname (if available)
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_online BOOLEAN DEFAULT TRUE,   -- Current status
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
);
```

### 2. **Connection Management**
```go
// DSN format: "username:password@tcp(hostname:port)/database"
db, err := database.NewMySQLDatabase("monitor:secret@tcp(localhost:3306)/monitoring")
if err != nil {
    log.Fatal("Database connection failed:", err)
}
defer db.Close()  // Cleanup when done
```

### 3. **Transaction Safety**
Although not implemented in the current version, here's how you'd add transactions:

```go
func (m *MySQLDatabase) UpdateHostWithTransaction(hostID int, status bool) error {
    tx, err := m.db.Begin()  // Start transaction
    if err != nil {
        return err
    }
    defer tx.Rollback()  // Rollback if not committed
    
    // Multiple operations...
    _, err = tx.Exec("UPDATE host SET is_online = ?, last_seen = NOW() WHERE id = ?", status, hostID)
    if err != nil {
        return err
    }
    
    return tx.Commit()  // Commit all changes
}
```

---

## API Integration

### 1. **Request Structure**
```go
type NewHostRequest struct {
    IPAddress   string `json:"ip_address"`
    MACAddress  string `json:"mac_address"`
    NetworkID   int    `json:"network_id"`
    Hostname    string `json:"hostname"`
    DetectedBy  string `json:"detected_by"`   // "ping", "arp", "port scan"
    OpenPort    int    `json:"open_port,omitempty"`
}
```

### 2. **HTTP Client Configuration**
```go
type Client struct {
    baseURL    string        // "https://api.example.com"
    httpClient *http.Client  // Configured HTTP client
    apiKey     string        // "Bearer token" or API key
}

func NewClient(baseURL, apiKey string) *Client {
    return &Client{
        baseURL: baseURL,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,  // Prevent hanging requests
        },
        apiKey: apiKey,
    }
}
```

### 3. **JWT Authentication Extension**
For JWT authentication instead of API keys, you could extend the client:

```go
type JWTClient struct {
    *Client
    username string
    password string
    token    string
    tokenExp time.Time
}

func (j *JWTClient) ensureValidToken() error {
    if time.Now().After(j.tokenExp) {
        return j.refreshToken()
    }
    return nil
}

func (j *JWTClient) refreshToken() error {
    loginReq := LoginRequest{
        Username: j.username,
        Password: j.password,
    }
    
    // POST to /auth/login
    resp, err := j.postJSON("/auth/login", loginReq)
    if err != nil {
        return err
    }
    
    var loginResp LoginResponse
    err = json.NewDecoder(resp.Body).Decode(&loginResp)
    if err != nil {
        return err
    }
    
    j.token = loginResp.Token
    j.tokenExp = time.Now().Add(time.Duration(loginResp.ExpiresIn) * time.Second)
    
    return nil
}

func (j *JWTClient) PostNewHost(host NewHostRequest) error {
    if err := j.ensureValidToken(); err != nil {
        return err
    }
    
    // Use j.token in Authorization header
    return j.Client.PostNewHost(host)
}
```

---

## Concurrency and Performance

### 1. **Goroutine Management**
```go
const numWorkers = 500  // Configurable worker count

// Create worker pool
for i := 0; i < numWorkers; i++ {
    go worker(ipChannel, results)
}
```

**Why 500 workers?**
- Network I/O bound operations can handle high concurrency
- Most time spent waiting for network responses
- Go's scheduler efficiently manages thousands of goroutines
- Can adjust based on system capabilities

### 2. **Channel Buffering**
```go
ipChannel := make(chan string, 1000)      // Buffered channel
results := make(chan HostStatus, 1000)    // Buffered channel
```

**Benefits of buffering:**
- Reduces blocking between producer and consumer
- Allows burst processing
- Improves overall throughput

### 3. **Memory Management**
```go
var aliveHosts []HostStatus
for checkedCount < expectedCount {
    result := <-results
    if result.Alive {
        aliveHosts = append(aliveHosts, result)  // Grows as needed
    }
}
```

**Slice growth pattern:**
- Go automatically doubles slice capacity when full
- Efficient for unknown result sizes
- Could pre-allocate if maximum size known

### 4. **Performance Monitoring**
```go
if checkedCount%5000 == 0 {
    progress := float64(checkedCount) / float64(expectedCount) * 100
    fmt.Printf("Progress: %d/%d (%.1f%%)\n", checkedCount, expectedCount, progress)
}
```

---

## Error Handling

### 1. **Error Wrapping Pattern**
```go
func processHost(ip string) error {
    status, err := scanHost(ip)
    if err != nil {
        return fmt.Errorf("failed to scan host %s: %w", ip, err)
    }
    
    err = saveToDatabase(status)
    if err != nil {
        return fmt.Errorf("failed to save host %s to database: %w", ip, err)
    }
    
    return nil
}
```

**Benefits:**
- Preserves original error with `%w` verb
- Adds context at each level
- Enables error unwrapping with `errors.Unwrap()`

### 2. **Graceful Degradation**
```go
if config != nil && config.Database != nil {
    knownHosts, err = loadKnownHosts(config.Database)
    if err != nil {
        fmt.Printf("⚠️ Warning: Could not load known hosts: %v\n", err)
        knownHosts = make(map[string]*database.Host)  // Continue without database
    }
}
```

**Pattern:**
- Log warnings for non-critical failures
- Provide fallback behavior
- Don't stop entire operation for partial failures

### 3. **Resource Cleanup**
```go
db, err := database.NewMySQLDatabase(dsn)
if err != nil {
    return fmt.Errorf("database connection failed: %w", err)
}
defer db.Close()  // Guaranteed cleanup
```

**defer keyword:**
- Executes when function returns (success or error)
- LIFO order (last defer runs first)
- Essential for resource management

---

## Future Modifications Guide

### 1. **Adding New Detection Methods**

To add a new host detection method:

```go
// In pkg/host/host.go, add to isHostAlive()
func isHostAlive(ip string) HostStatus {
    // ... existing methods ...
    
    // Method 4: Your new method
    if checkCustomMethod(ip) {
        status.Alive = true
        status.Method = "custom"
        return status
    }
    
    return status
}

func checkCustomMethod(ip string) bool {
    // Your detection logic here
    return false
}
```

### 2. **Adding JWT Authentication**

Since you mentioned your API might require JWT instead of API keys, here's how to implement it:

```go
// In pkg/api/client.go - Add JWT support

type JWTClient struct {
    *Client
    username   string
    password   string
    token      string
    tokenExp   time.Time
    loginURL   string
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type LoginResponse struct {
    Token     string `json:"token"`
    ExpiresIn int    `json:"expires_in"` // seconds
    Success   bool   `json:"success"`
}

func NewJWTClient(baseURL, username, password string) *JWTClient {
    return &JWTClient{
        Client: &Client{
            baseURL: baseURL,
            httpClient: &http.Client{
                Timeout: 30 * time.Second,
            },
        },
        username: username,
        password: password,
        loginURL: baseURL + "/auth/login",
    }
}

func (j *JWTClient) ensureValidToken() error {
    // Check if token is expired (with 5 minute buffer)
    if time.Now().Add(5*time.Minute).After(j.tokenExp) {
        return j.refreshToken()
    }
    return nil
}

func (j *JWTClient) refreshToken() error {
    loginReq := LoginRequest{
        Username: j.username,
        Password: j.password,
    }
    
    jsonData, err := json.Marshal(loginReq)
    if err != nil {
        return fmt.Errorf("failed to marshal login request: %w", err)
    }
    
    req, err := http.NewRequest("POST", j.loginURL, bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("failed to create login request: %w", err)
    }
    
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := j.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("login request failed: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != 200 {
        return fmt.Errorf("login failed with status %d", resp.StatusCode)
    }
    
    var loginResp LoginResponse
    err = json.NewDecoder(resp.Body).Decode(&loginResp)
    if err != nil {
        return fmt.Errorf("failed to decode login response: %w", err)
    }
    
    if !loginResp.Success {
        return fmt.Errorf("login was not successful")
    }
    
    j.token = loginResp.Token
    j.tokenExp = time.Now().Add(time.Duration(loginResp.ExpiresIn) * time.Second)
    
    fmt.Printf("🔑 JWT token refreshed, expires at %s\n", j.tokenExp.Format("15:04:05"))
    return nil
}

// Override PostNewHost to use JWT authentication
func (j *JWTClient) PostNewHost(host NewHostRequest) error {
    if err := j.ensureValidToken(); err != nil {
        return fmt.Errorf("failed to ensure valid token: %w", err)
    }
    
    jsonData, err := json.Marshal(host)
    if err != nil {
        return fmt.Errorf("failed to marshal JSON: %w", err)
    }
    
    url := j.baseURL + "/api/hosts"
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return fmt.Errorf("failed to create request: %w", err)
    }
    
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "Bearer "+j.token)  // Use JWT token
    
    resp, err := j.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("failed to send request: %w", err)
    }
    defer resp.Body.Close()
    
    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        // If 401, try refreshing token once
        if resp.StatusCode == 401 {
            if err := j.refreshToken(); err != nil {
                return fmt.Errorf("failed to refresh token after 401: %w", err)
            }
            // Retry request with new token
            req.Header.Set("Authorization", "Bearer "+j.token)
            resp, err = j.httpClient.Do(req)
            if err != nil {
                return fmt.Errorf("retry request failed: %w", err)
            }
            defer resp.Body.Close()
        }
        
        if resp.StatusCode < 200 || resp.StatusCode >= 300 {
            return fmt.Errorf("API request failed with status %d", resp.StatusCode)
        }
    }
    
    return nil
}

// Similarly implement PostNewNetwork for JWT client
func (j *JWTClient) PostNewNetwork(network NewNetworkRequest) error {
    // Similar implementation with JWT token
}
```

**Command line usage with JWT:**
```bash
# Add new flags to cmd/hosts.go
hostsCmd.Flags().String("api-username", "", "API username for JWT authentication")
hostsCmd.Flags().String("api-password", "", "API password for JWT authentication") 
hostsCmd.Flags().Bool("api-use-jwt", false, "Use JWT authentication instead of API key")

# Usage:
./monitor-go hosts \
  --db-dsn "user:pass@tcp(localhost:3306)/monitor" \
  --api-url "https://your-api.com" \
  --api-use-jwt \
  --api-username "your-username" \
  --api-password "your-password"
```

### 3. **Adding New Output Formats**

To add XML output format:

```go
// In pkg/report/report.go
func (r *ScanReport) WriteToFile(filename string) error {
    // ... existing code ...
    
    switch ext {
    case "json":
        content, err = r.ToJSON()
    case "xml":
        content, err = r.ToXML()  // New method
    // ... other cases ...
    }
}

func (r *ScanReport) ToXML() ([]byte, error) {
    return xml.MarshalIndent(r, "", "  ")
}
```

### 3. **Adding Configuration File Support**

Using Viper for configuration:

```go
// Add to imports
"github.com/spf13/viper"

// In cmd/root.go or hosts.go
func initConfig() {
    viper.SetConfigName("monitor-go")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.AddConfigPath("$HOME/.monitor-go")
    
    if err := viper.ReadInConfig(); err == nil {
        fmt.Println("Using config file:", viper.ConfigFileUsed())
    }
}

// Use in command
dbDSN := viper.GetString("database.dsn")
apiURL := viper.GetString("api.url")
```

### 4. **Adding Metrics/Monitoring**

For Prometheus metrics:

```go
// Add prometheus client
import "github.com/prometheus/client_golang/prometheus"

var (
    hostsScanned = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "hosts_scanned_total",
            Help: "Total number of hosts scanned",
        },
        []string{"method", "status"},
    )
)

func init() {
    prometheus.MustRegister(hostsScanned)
}

// In scanning code
hostsScanned.WithLabelValues(result.Method, "alive").Inc()
```

### 5. **Improving Database Performance**

For bulk operations:

```go
func (m *MySQLDatabase) BulkUpdateHosts(updates []HostUpdate) error {
    tx, err := m.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    stmt, err := tx.Prepare("UPDATE host SET is_online = ?, last_seen = ? WHERE id = ?")
    if err != nil {
        return err
    }
    defer stmt.Close()
    
    for _, update := range updates {
        _, err = stmt.Exec(update.IsOnline, update.LastSeen, update.ID)
        if err != nil {
            return err
        }
    }
    
    return tx.Commit()
}
```

### 6. **Adding Web Interface**

Using Gin web framework:

```go
import "github.com/gin-gonic/gin"

func startWebServer(scanner *host.Scanner) {
    r := gin.Default()
    
    r.GET("/api/hosts", func(c *gin.Context) {
        hosts, err := scanner.GetKnownHosts()
        if err != nil {
            c.JSON(500, gin.H{"error": err.Error()})
            return
        }
        c.JSON(200, hosts)
    })
    
    r.POST("/api/scan", func(c *gin.Context) {
        go scanner.StartScan()  // Async scan
        c.JSON(202, gin.H{"message": "Scan started"})
    })
    
    r.Run(":8080")
}
```

---

## Testing Guide

### 1. **Unit Testing Example**
```go
// host_test.go
package host

import (
    "testing"
    "time"
)

func TestHostStatus_IsOnline(t *testing.T) {
    tests := []struct {
        name     string
        status   HostStatus
        expected bool
    }{
        {
            name:     "alive host",
            status:   HostStatus{IP: "192.168.1.1", Alive: true},
            expected: true,
        },
        {
            name:     "dead host",
            status:   HostStatus{IP: "192.168.1.2", Alive: false},
            expected: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := tt.status.Alive; got != tt.expected {
                t.Errorf("HostStatus.Alive = %v, want %v", got, tt.expected)
            }
        })
    }
}
```

### 2. **Mock Database for Testing**
```go
type MockDatabase struct {
    hosts []database.Host
}

func (m *MockDatabase) GetHosts() ([]database.Host, error) {
    return m.hosts, nil
}

func (m *MockDatabase) CreateHost(host *database.Host) error {
    host.ID = len(m.hosts) + 1
    m.hosts = append(m.hosts, *host)
    return nil
}

// Use in tests
func TestScanWithDatabase(t *testing.T) {
    mockDB := &MockDatabase{}
    config := &ScanConfig{Database: mockDB}
    
    // Test scanning logic
}
```

---

## Conclusion

This monitor-go application demonstrates several important Go concepts:

1. **Modular Design**: Clear separation of concerns across packages
2. **Interface Usage**: Database and API clients use interfaces for flexibility
3. **Concurrency**: Goroutines and channels for parallel network scanning
4. **Error Handling**: Comprehensive error wrapping and graceful degradation
5. **CLI Framework**: Cobra for professional command-line interface
6. **Database Integration**: Standard SQL package with proper connection management
7. **HTTP Client**: Custom client with timeout and authentication
8. **Multiple Output Formats**: Flexible report generation

The application is designed to be extensible and maintainable, with clear patterns you can follow to add new features. The concurrent scanning architecture makes it performant for large networks, while the database integration enables long-term host tracking and trend analysis.

Feel free to experiment with the code and add new features following the established patterns!
