package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// DatabaseInterface defines the interface for database operations
type DatabaseInterface interface {
	// Network operations
	GetNetworks() ([]Network, error)
	GetNetworkByIPAndMask(ipAddress, cidrMask string) (*Network, error)
	CreateNetwork(network *Network) error
	UpdateNetworkStatus(id int, isOnline bool) error

	// Host operations
	GetHosts() ([]Host, error)
	GetHostByIP(ipAddress string) (*Host, error)
	GetHostsByNetworkID(networkID int) ([]Host, error)
	CreateHost(host *Host) error
	UpdateHostStatus(id int, isOnline bool, lastSeen time.Time) error
	UpdateHostLastSeen(id int, lastSeen time.Time) error

	// Database connection
	Close() error
	Ping() error
}

// MySQLDatabase implements DatabaseInterface for MySQL
type MySQLDatabase struct {
	db *sql.DB
}

// NewMySQLDatabase creates a new MySQL database connection
func NewMySQLDatabase(dsn string) (*MySQLDatabase, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &MySQLDatabase{db: db}, nil
}

// Close closes the database connection
func (m *MySQLDatabase) Close() error {
	if m.db != nil {
		return m.db.Close()
	}
	return nil
}

// Ping tests the database connection
func (m *MySQLDatabase) Ping() error {
	return m.db.Ping()
}

// Network operations
func (m *MySQLDatabase) GetNetworks() ([]Network, error) {
	query := "SELECT id, ip_address, cidr_mask, description, is_online FROM networks"
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var network Network
		err := rows.Scan(&network.ID, &network.IPAddress, &network.CIDRMask, &network.Description, &network.IsOnline)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}

	return networks, rows.Err()
}

func (m *MySQLDatabase) GetNetworkByIPAndMask(ipAddress, cidrMask string) (*Network, error) {
	query := "SELECT id, ip_address, cidr_mask, description, is_online FROM networks WHERE ip_address = ? AND cidr_mask = ?"
	row := m.db.QueryRow(query, ipAddress, cidrMask)

	var network Network
	err := row.Scan(&network.ID, &network.IPAddress, &network.CIDRMask, &network.Description, &network.IsOnline)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &network, nil
}

func (m *MySQLDatabase) CreateNetwork(network *Network) error {
	query := "INSERT INTO networks (ip_address, cidr_mask, description, is_online) VALUES (?, ?, ?, ?)"
	result, err := m.db.Exec(query, network.IPAddress, network.CIDRMask, network.Description, network.IsOnline)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	network.ID = int(id)
	return nil
}

func (m *MySQLDatabase) UpdateNetworkStatus(id int, isOnline bool) error {
	query := "UPDATE networks SET is_online = ? WHERE id = ?"
	_, err := m.db.Exec(query, isOnline, id)
	return err
}

// Host operations
func (m *MySQLDatabase) GetHosts() ([]Host, error) {
	query := "SELECT id, mac_address, ip_address, network_id, hostname, first_seen, last_seen, is_online FROM host"
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var host Host
		err := rows.Scan(&host.ID, &host.MACAddress, &host.IPAddress, &host.NetworkID, &host.Hostname, &host.FirstSeen, &host.LastSeen, &host.IsOnline)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	return hosts, rows.Err()
}

func (m *MySQLDatabase) GetHostByIP(ipAddress string) (*Host, error) {
	query := "SELECT id, mac_address, ip_address, network_id, hostname, first_seen, last_seen, is_online FROM host WHERE ip_address = ?"
	row := m.db.QueryRow(query, ipAddress)

	var host Host
	err := row.Scan(&host.ID, &host.MACAddress, &host.IPAddress, &host.NetworkID, &host.Hostname, &host.FirstSeen, &host.LastSeen, &host.IsOnline)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &host, nil
}

func (m *MySQLDatabase) GetHostsByNetworkID(networkID int) ([]Host, error) {
	query := "SELECT id, mac_address, ip_address, network_id, hostname, first_seen, last_seen, is_online FROM host WHERE network_id = ?"
	rows, err := m.db.Query(query, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []Host
	for rows.Next() {
		var host Host
		err := rows.Scan(&host.ID, &host.MACAddress, &host.IPAddress, &host.NetworkID, &host.Hostname, &host.FirstSeen, &host.LastSeen, &host.IsOnline)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	return hosts, rows.Err()
}

func (m *MySQLDatabase) CreateHost(host *Host) error {
	query := "INSERT INTO host (mac_address, ip_address, network_id, hostname, first_seen, last_seen, is_online) VALUES (?, ?, ?, ?, ?, ?, ?)"
	result, err := m.db.Exec(query, host.MACAddress, host.IPAddress, host.NetworkID, host.Hostname, host.FirstSeen, host.LastSeen, host.IsOnline)
	if err != nil {
		return err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return err
	}

	host.ID = int(id)
	return nil
}

func (m *MySQLDatabase) UpdateHostStatus(id int, isOnline bool, lastSeen time.Time) error {
	query := "UPDATE host SET is_online = ?, last_seen = ? WHERE id = ?"
	_, err := m.db.Exec(query, isOnline, lastSeen, id)
	return err
}

func (m *MySQLDatabase) UpdateHostLastSeen(id int, lastSeen time.Time) error {
	query := "UPDATE host SET last_seen = ? WHERE id = ?"
	_, err := m.db.Exec(query, lastSeen, id)
	return err
}
