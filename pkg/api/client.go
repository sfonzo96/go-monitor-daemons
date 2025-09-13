package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sfonzo96/monitor-go/pkg/database"
)

// Client represents an API client for monitoring system
type Client struct {
	baseURL    string
	httpClient *http.Client
	apiKey     string
}

// NewClient creates a new API client
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		apiKey: apiKey,
	}
}

// NewHostRequest represents the payload for creating a new host
type NewHostRequest struct {
	IPAddress  string `json:"ip_address"`
	MACAddress string `json:"mac_address"`
	NetworkID  int    `json:"network_id"`
	Hostname   string `json:"hostname"`
	DetectedBy string `json:"detected_by"` // ping, arp, port scan
	OpenPort   int    `json:"open_port,omitempty"`
}

// NewNetworkRequest represents the payload for creating a new network
type NewNetworkRequest struct {
	IPAddress   string `json:"ip_address"`
	CIDRMask    string `json:"cidr_mask"`
	Description string `json:"description"`
	IsOnline    bool   `json:"is_online"`
}

// PostNewHost sends a new host discovery to the API
func (c *Client) PostNewHost(host NewHostRequest) error {
	return c.postJSON("/api/hosts", host)
}

// PostNewNetwork sends a new network discovery to the API
func (c *Client) PostNewNetwork(network NewNetworkRequest) error {
	return c.postJSON("/api/networks", network)
}

// postJSON is a helper method to post JSON data
func (c *Client) postJSON(endpoint string, payload interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	url := c.baseURL + endpoint
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
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	return nil
}

// ConvertHostToAPIRequest converts a database Host to API request format
func ConvertHostToAPIRequest(host database.Host, detectedBy string, openPort int) NewHostRequest {
	return NewHostRequest{
		IPAddress:  host.IPAddress,
		MACAddress: host.MACAddress,
		NetworkID:  host.NetworkID,
		Hostname:   host.Hostname,
		DetectedBy: detectedBy,
		OpenPort:   openPort,
	}
}

// ConvertNetworkToAPIRequest converts a database Network to API request format
func ConvertNetworkToAPIRequest(network database.Network) NewNetworkRequest {
	return NewNetworkRequest{
		IPAddress:   network.IPAddress,
		CIDRMask:    network.CIDRMask,
		Description: network.Description,
		IsOnline:    network.IsOnline,
	}
}
