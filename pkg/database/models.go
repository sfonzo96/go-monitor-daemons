package database

import (
	"time"
)

// Network represents a network entity in the database
type Network struct {
	ID          int    `json:"id" db:"id"`
	IPAddress   string `json:"ip_address" db:"ip_address"`
	CIDRMask    string `json:"cidr_mask" db:"cidr_mask"`
	Description string `json:"description" db:"description"`
	IsOnline    bool   `json:"is_online" db:"is_online"`
}

// Host represents a host entity in the database
type Host struct {
	ID         int       `json:"id" db:"id"`
	MACAddress string    `json:"mac_address" db:"mac_address"`
	IPAddress  string    `json:"ip_address" db:"ip_address"`
	NetworkID  int       `json:"network_id" db:"network_id"`
	Hostname   string    `json:"hostname" db:"hostname"`
	FirstSeen  time.Time `json:"first_seen" db:"first_seen"`
	LastSeen   time.Time `json:"last_seen" db:"last_seen"`
	IsOnline   bool      `json:"is_online" db:"is_online"`
}

// HostWithNetwork represents a host with its network information
type HostWithNetwork struct {
	Host
	Network Network `json:"network"`
}
