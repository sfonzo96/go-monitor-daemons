package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
	jwt        string
}

// Comment: Decorator pattern to create a new API client with default settings
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

type NewHostRequest struct {
	IPAddress  string `json:"ipAddress"`
	MACAddress string `json:"macAddress"`
	NetworkID  int    `json:"networkId"`
	Hostname   string `json:"hostname"`
}

type NewNetworkRequest struct {
	IPAddress   string `json:"ipAddress"`
	CIDRMask    int    `json:"CIDRMask"`
	Description string `json:"description"`
}

type NewMetricRecordRequest struct {
	MetricId int     `json:"metricId"`
	Value    float64 `json:"value"`
}

type LoginResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Token string `json:"accessToken"`
	} `json:"data"`
}

type GenericResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

type ErrorResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Data    struct {
		Errors map[string][]string `json:"errors"`
	} `json:"data"`
}

type JWTData struct {
	Exp int64 `json:"exp"`
}

func (c *Client) LoginAndGetJWT(username, password string) (string, error) {
	client := http.Client{
		Timeout: 10 * time.Second,
	}

	url := c.baseURL + "/auth/login"
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	jwt, err := extractJwtFromResponse(resp)
	if err != nil {
		return "", fmt.Errorf("failed to extract JWT: %w", err)
	}

	c.jwt = jwt
	return jwt, nil
}

func extractJwtFromResponse(resp *http.Response) (string, error) {
	var result LoginResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode login response: %w", err)
	}
	return result.Data.Token, nil
}

func (c *Client) Post(endpoint string, payload any) error {
	if c.jwt == "" || c.isJWTExpired() {
		jwt, err := c.LoginAndGetJWT(os.Getenv("LOGIN_USER"), os.Getenv("LOGIN_PASSWORD"))
		if err != nil {
			return fmt.Errorf("failed to login: %w", err)
		}
		c.jwt = jwt
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	url := c.baseURL + endpoint
	fmt.Println("Posting to URL:", url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.jwt)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return fmt.Errorf("failed to decode error response: %w", err)
		}
		fmt.Printf("API request failed with status %d: %s", resp.StatusCode, apiErr.Message)
	}

	// Comment: If < 400 I assume success and do nothingi

	return nil
}

func (c *Client) isJWTExpired() bool {
	parts := strings.Split(c.jwt, ".")
	if len(parts) != 3 {
		return true // Comment: Invalid format, assumed expired
	}

	payload := parts[1] // Comment: only payload is needed

	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return true
	}

	var claims JWTData
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return true
	}

	return time.Now().Unix() >= (claims.Exp - 5) // Comment: si faltan 5 segundos para expirar, lo considero expirado
}
