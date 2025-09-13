# Monitor-Go Configuration Examples

## Database Setup
Before using database features, create the required tables:

```sql
-- NETWORK
CREATE TABLE IF NOT EXISTS networks (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    cidr_mask VARCHAR(45),
    description VARCHAR(50),
    is_online BOOLEAN, -- Online means that the device where the monitoring system is on is connected to it
    UNIQUE KEY uniq_network (ip_address, cidr_mask)
);

-- HOST
CREATE TABLE IF NOT EXISTS host (
    id INT AUTO_INCREMENT PRIMARY KEY,
    mac_address VARCHAR(255),
    ip_address VARCHAR(45) NOT NULL,
    network_id INT NOT NULL,
    hostname VARCHAR(255),
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_online BOOLEAN DEFAULT TRUE, -- Online means it's detected on one of the last scans
    FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
);
```

## Usage Examples

### Basic Scan (Original Functionality)
```bash
./monitor-go hosts
```

### Save Results to Different Formats
```bash
# JSON format
./monitor-go hosts --output scan_results.json

# Text format
./monitor-go hosts --output scan_results.txt

# CSV format
./monitor-go hosts --output scan_results.csv
```

### Database Integration
```bash
# Connect to MySQL database to track known hosts
./monitor-go hosts --db-dsn "username:password@tcp(localhost:3306)/monitor_db"

# Combine database tracking with file output
./monitor-go hosts --db-dsn "username:password@tcp(localhost:3306)/monitor_db" --output detailed_report.json
```

### API Integration for New Host Notifications
```bash
# Send new host discoveries to API
./monitor-go hosts --api-url "https://api.monitor.example.com" --api-key "your-api-key-here"

# Full integration: database tracking + API notifications + file output
./monitor-go hosts \
  --db-dsn "username:password@tcp(localhost:3306)/monitor_db" \
  --api-url "https://api.monitor.example.com" \
  --api-key "your-api-key-here" \
  --output comprehensive_scan.json
```

## Behavior Summary

### Business Logic Overview
The application implements a clear separation of concerns:

1. **New Discoveries → API**: Unknown hosts and networks are sent to your external API
2. **Known Entities → Database**: Status changes for known hosts are handled directly via database
3. **Reporting → Files**: Scan results can be exported in multiple formats

### Database Integration Logic
When a database is configured, the system will:

1. **For Known Hosts (Direct Database Updates):**
   - If host is alive AND database status is FALSE → Update to TRUE
   - If host is alive AND database status is TRUE → Update last_seen timestamp
   - If host is NOT alive AND database status is TRUE → Update to FALSE

2. **For Unknown Hosts (API Integration):**
   - If host is alive → POST to API (if configured)

3. **For Networks:**
   - Check discovered networks against database
   - If network is unknown → POST to API (if configured)

### API Integration
When API is configured, new discoveries are automatically sent as JSON payloads:

**New Host Discovery:**
```json
POST /api/hosts
{
  "ip_address": "192.168.1.100",
  "mac_address": "",
  "network_id": 1,
  "hostname": "",
  "detected_by": "ping",
  "open_port": 22
}
```

**New Network Discovery:**
```json
POST /api/networks
{
  "ip_address": "192.168.1.0",
  "cidr_mask": "/24",
  "description": "Auto-discovered network 192.168.1.0/24",
  "is_online": true
}
```

### Error Handling
The application implements graceful degradation:
- Database connection failures → Continue scanning without persistence
- API request failures → Log warnings but continue operation
- Network scanning errors → Skip problematic networks, continue with others

## Periodic Execution
For background monitoring, you can set up the tool to run periodically:

```bash
# Example cron job (every 30 minutes)
*/30 * * * * /path/to/monitor-go hosts --db-dsn "user:pass@tcp(localhost:3306)/monitor" --api-url "https://api.example.com" --api-key "secret" --output /var/log/monitor/scan_$(date +\%Y\%m\%d_\%H\%M).json
```

## Troubleshooting

### Common Issues

#### Database Connection Problems
```bash
# Test database connectivity
./monitor-go hosts --db-dsn "user:pass@tcp(localhost:3306)/monitor_db"

# Common errors:
# - "connection refused" → Check MySQL is running and accessible
# - "access denied" → Verify username/password/database name
# - "unknown database" → Create the database and tables first
```

#### API Integration Issues
```bash
# Test API connectivity (without database)
./monitor-go hosts --api-url "https://your-api.com" --api-key "your-key"

# Common errors:
# - "connection timeout" → Check API URL and network connectivity
# - "401 Unauthorized" → Verify API key is correct
# - "404 Not Found" → Ensure API endpoints /api/hosts and /api/networks exist
```

#### Performance Tuning
```bash
# For large networks, monitor progress
./monitor-go hosts --output large_scan.json 2>&1 | tee scan.log

# Expected performance:
# - Small networks (/24): ~30 seconds
# - Medium networks (/20): ~2-5 minutes  
# - Large networks (/16): ~10-30 minutes
```

### Debug Information
Add these environment variables for detailed logging:
```bash
export DEBUG=1
./monitor-go hosts --db-dsn "..." --api-url "..."
```

### Network Scanning Behavior
- **Ping Method**: Fastest, works for most Linux/Windows hosts
- **Port Scan Method**: Detects firewalled hosts with open services
- **ARP Method**: Finds recently contacted hosts (same network segment)

The tool tries methods in order and stops at first success for efficiency.
