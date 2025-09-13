# Monitor-Go

A high-performance network monitoring tool written in Go that discovers hosts on local networks with database persistence and API integration capabilities.

## 🚀 Quick Start

```bash
# Basic network scan
./monitor-go hosts

# Save results to file
./monitor-go hosts --output scan_results.json

# Full integration with database and API
./monitor-go hosts \
  --db-dsn "user:pass@tcp(localhost:3306)/monitor_db" \
  --api-url "https://api.example.com" \
  --api-key "your-api-key" \
  --output comprehensive_report.json
```

## ✨ Features

- **🔍 Multi-Method Host Detection**
  - ICMP ping scanning
  - TCP port scanning (common ports)
  - ARP table lookup
  - Concurrent scanning with 500 workers

- **💾 Database Integration**
  - MySQL support for host/network tracking
  - Automatic status updates for known hosts
  - Persistent host history with timestamps

- **🌐 API Integration**
  - HTTP client for external system notifications
  - Automatic posting of new host/network discoveries
  - Configurable authentication (API key support, JWT ready)

- **📊 Flexible Reporting**
  - JSON, CSV, and TXT output formats
  - Detailed scan statistics and summaries
  - Progress tracking for large networks

- **⚡ High Performance**
  - Concurrent scanning architecture
  - Efficient worker pool pattern
  - Graceful handling of network timeouts

## 📋 Business Logic

The application implements intelligent discovery management:

- **Known Hosts** → Direct database updates (status changes, timestamps)
- **New Hosts** → API notifications for business logic processing
- **New Networks** → API notifications for infrastructure tracking
- **Error Handling** → Graceful degradation, continues operation on partial failures

## 🛠️ Installation & Setup

### Prerequisites
- Go 1.18+ 
- MySQL database (optional)
- Network access for scanning

### Build from Source
```bash
git clone <repository>
cd monitor-go
go mod tidy
go build -o monitor-go
```

### Database Setup
```sql
CREATE DATABASE monitor_db;
-- See CONFIG.md for complete table schemas
```

## 📚 Documentation

- **[CONFIG.md](CONFIG.md)** - Configuration examples and usage patterns
- **[TECHNICAL_GUIDE.md](TECHNICAL_GUIDE.md)** - Complete technical documentation for developers
- **[notes.md](notes.md)** - Development notes and completed features

## 🔧 Configuration

### Command Line Options
```bash
Flags:
  --api-key string     API key for authentication
  --api-url string     API base URL for posting discoveries
  --db-dsn string      Database DSN (user:pass@tcp(host:port)/db)
  -o, --output string  Output file (supports .json, .txt, .csv)
  -h, --help           Help for hosts command
```

### Environment Variables
```bash
export MONITOR_DB_DSN="user:pass@tcp(localhost:3306)/monitor_db"
export MONITOR_API_URL="https://api.example.com"
export MONITOR_API_KEY="your-api-key"
```

## 🎯 Use Cases

### Network Administration
- Automated host discovery and inventory
- Network topology mapping
- Change detection and alerting

### Security Monitoring  
- Unauthorized device detection
- Network access compliance
- Infrastructure monitoring

### DevOps Integration
- Infrastructure as Code validation
- Continuous infrastructure monitoring
- API-driven network management

## 🚦 API Endpoints

Your external API should implement these endpoints:

```bash
POST /api/hosts     # New host discoveries
POST /api/networks  # New network discoveries
```

See **[TECHNICAL_GUIDE.md](TECHNICAL_GUIDE.md)** for complete API payload specifications.

## 🔄 Periodic Monitoring

Set up automated scanning with cron:

```bash
# Every 30 minutes
*/30 * * * * /path/to/monitor-go hosts --db-dsn "..." --api-url "..." --output /var/log/monitor/scan_$(date +\%Y\%m\%d_\%H\%M).json
```

## 🤝 Contributing

This tool is designed for extensibility. Key extension points:

- **Detection Methods** - Add new host discovery techniques
- **Output Formats** - Implement additional report formats  
- **Authentication** - Extend API client capabilities
- **Database Backends** - Support additional database types

See **[TECHNICAL_GUIDE.md](TECHNICAL_GUIDE.md)** for detailed modification instructions.

## 📄 License

See LICENSE file for details.

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   CLI Command   │───▶│  Host Scanner    │───▶│   Report Gen    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                           │
                              ▼                           ▼
                    ┌──────────────────┐          ┌─────────────────┐
                    │    Database      │          │   File Output   │
                    │   (Known Hosts)  │          │ (JSON/CSV/TXT)  │
                    └──────────────────┘          └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   External API   │
                    │ (New Discoveries)│
                    └──────────────────┘
```

Built with ❤️ in Go for network administrators and DevOps engineers.
