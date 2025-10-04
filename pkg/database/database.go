package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type DatabaseInterface interface {
	GetNetworks() ([]NetworkModel, error)

	GetHostsByNetworkID(networkID int) ([]HostModel, error)
	UpdateHostStatus(id int, isOnline bool, lastSeen time.Time) error

	Close() error
}

type MySQLDatabase struct {
	db *sql.DB
}

func NewMySQLDatabase(dsn string) (*MySQLDatabase, error) {
	db, err := sql.Open("mysql", dsn+"?charset=utf8mb4&parseTime=true&loc=Local")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &MySQLDatabase{db: db}, nil
}

func (m *MySQLDatabase) GetNetworks() ([]NetworkModel, error) {
	query := "SELECT id, ip_address, cidr_mask, description FROM networks"
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []NetworkModel
	for rows.Next() {
		var network NetworkModel
		err := rows.Scan(&network.ID, &network.IPAddress, &network.CIDRMask, &network.Description)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}

	return networks, rows.Err()
}

func (m *MySQLDatabase) GetHostsByNetworkID(networkID int) ([]HostModel, error) {
	query := "SELECT id, mac_address, ip_address, network_id, hostname, first_seen, last_seen, is_online FROM hosts WHERE network_id = ?"
	rows, err := m.db.Query(query, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []HostModel
	for rows.Next() {
		var host HostModel
		err := rows.Scan(&host.ID, &host.MACAddress, &host.IPAddress, &host.NetworkID, &host.Hostname, &host.FirstSeen, &host.LastSeen, &host.IsOnline)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, host)
	}

	return hosts, rows.Err()
}

func (m *MySQLDatabase) UpdateHostStatus(id int, isOnline bool) error {
	queryOnline := "UPDATE hosts SET is_online = ?, last_seen = ? WHERE id = ?"
	queryOffline := "UPDATE hosts SET is_online = ? WHERE id = ?"
	if isOnline {
		_, err := m.db.Exec(queryOnline, isOnline, time.Now(), id)
		return err
	} else {
		_, err := m.db.Exec(queryOffline, isOnline, id)
		return err
	}
}

func (m *MySQLDatabase) Close() error {
	return m.db.Close()
}
