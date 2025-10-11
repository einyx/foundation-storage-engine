package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Client provides OPA policy evaluation functionality
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new OPA client with the specified URL and timeout
func NewClient(url string, timeout time.Duration) *Client {
	return &Client{
		baseURL: url,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

// Input represents the input structure for OPA policy evaluation
type Input struct {
	User     string   `json:"user"`
	Action   string   `json:"action"`
	Resource Resource `json:"resource"`
}

// Resource represents the resource being accessed
type Resource struct {
	ID           string   `json:"id,omitempty"`
	Organization string   `json:"organization"`
	Type         string   `json:"type"`
	Bucket       string   `json:"bucket,omitempty"`
	Key          string   `json:"key,omitempty"`
	Tags         []string `json:"tags,omitempty"`
}

// PolicyRequest represents the request payload for OPA evaluation
type PolicyRequest struct {
	Input Input `json:"input"`
}

// PolicyResponse represents the response from OPA evaluation
type PolicyResponse struct {
	Result bool `json:"result"`
}

// Evaluate sends a policy evaluation request to OPA and returns the decision
func (c *Client) Evaluate(ctx context.Context, input Input) (bool, error) {
	request := PolicyRequest{Input: input}
	
	jsonData, err := json.Marshal(request)
	if err != nil {
		return false, fmt.Errorf("failed to marshal OPA request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/data/meshx/authz/allow", c.baseURL)
	
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Errorf("failed to create OPA request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to send OPA request: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned status %d", resp.StatusCode)
	}
	
	var policyResponse PolicyResponse
	if err := json.NewDecoder(resp.Body).Decode(&policyResponse); err != nil {
		return false, fmt.Errorf("failed to decode OPA response: %w", err)
	}
	
	return policyResponse.Result, nil
}