package database

import (
	"time"
)

type NetworkModel struct {
	ID          *int   `json:"id" db:"id"`
	IPAddress   string `json:"ipAddress" db:"ip_address"`
	CIDRMask    string `json:"cidrMask" db:"cidr_mask"`
	Description string `json:"description" db:"description"`
}

type HostModel struct {
	ID         *int       `json:"id" db:"id"`
	MACAddress string     `json:"macAddress" db:"mac_address"`
	IPAddress  string     `json:"ipAddress" db:"ip_address"`
	NetworkID  int        `json:"networkId" db:"network_id"`
	Hostname   string     `json:"hostname" db:"hostname"`
	FirstSeen  *time.Time `json:"firstSeen" db:"first_seen"`
	LastSeen   *time.Time `json:"lastSeen" db:"last_seen"`
	IsOnline   *bool      `json:"isOnline" db:"is_online"`
}
