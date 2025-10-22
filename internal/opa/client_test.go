package opa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	url := "http://opa.example.com:8181"
	timeout := 30 * time.Second

	client := NewClient(url, timeout)

	if client == nil {
		t.Fatal("NewClient returned nil")
	}

	if client.baseURL != url {
		t.Errorf("Expected baseURL %s, got %s", url, client.baseURL)
	}

	if client.httpClient == nil {
		t.Fatal("HTTP client should not be nil")
	}

	if client.httpClient.Timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, client.httpClient.Timeout)
	}
}

func TestNewClient_ZeroTimeout(t *testing.T) {
	url := "http://opa.example.com:8181"
	timeout := time.Duration(0)

	client := NewClient(url, timeout)

	if client.httpClient.Timeout != 0 {
		t.Errorf("Expected zero timeout, got %v", client.httpClient.Timeout)
	}
}

func TestInput_Fields(t *testing.T) {
	input := Input{
		User:   "user123",
		Action: "READ",
		Resource: Resource{
			ID:           "resource-1",
			Organization: "org1",
			Type:         "bucket",
			Bucket:       "my-bucket",
			Key:          "path/to/object",
			Tags:         []string{"env:prod", "team:platform"},
		},
	}

	if input.User != "user123" {
		t.Errorf("Expected user 'user123', got '%s'", input.User)
	}

	if input.Action != "READ" {
		t.Errorf("Expected action 'READ', got '%s'", input.Action)
	}

	if input.Resource.Organization != "org1" {
		t.Errorf("Expected organization 'org1', got '%s'", input.Resource.Organization)
	}

	if input.Resource.Bucket != "my-bucket" {
		t.Errorf("Expected bucket 'my-bucket', got '%s'", input.Resource.Bucket)
	}

	if len(input.Resource.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(input.Resource.Tags))
	}
}

func TestResource_MinimalFields(t *testing.T) {
	resource := Resource{
		Organization: "org1",
		Type:         "object",
	}

	if resource.Organization != "org1" {
		t.Errorf("Expected organization 'org1', got '%s'", resource.Organization)
	}

	if resource.Type != "object" {
		t.Errorf("Expected type 'object', got '%s'", resource.Type)
	}

	// Optional fields should be empty
	if resource.ID != "" {
		t.Errorf("Expected empty ID, got '%s'", resource.ID)
	}

	if resource.Bucket != "" {
		t.Errorf("Expected empty bucket, got '%s'", resource.Bucket)
	}

	if resource.Key != "" {
		t.Errorf("Expected empty key, got '%s'", resource.Key)
	}

	if len(resource.Tags) != 0 {
		t.Errorf("Expected no tags, got %d", len(resource.Tags))
	}
}

func TestPolicyRequest_JSON(t *testing.T) {
	request := PolicyRequest{
		Input: Input{
			User:   "alice",
			Action: "WRITE",
			Resource: Resource{
				Organization: "acme",
				Type:         "bucket",
				Bucket:       "test-bucket",
			},
		},
	}

	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Failed to marshal PolicyRequest: %v", err)
	}

	// Verify the JSON structure
	var unmarshaled PolicyRequest
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal PolicyRequest: %v", err)
	}

	if unmarshaled.Input.User != "alice" {
		t.Errorf("Expected user 'alice', got '%s'", unmarshaled.Input.User)
	}

	if unmarshaled.Input.Action != "WRITE" {
		t.Errorf("Expected action 'WRITE', got '%s'", unmarshaled.Input.Action)
	}

	if unmarshaled.Input.Resource.Bucket != "test-bucket" {
		t.Errorf("Expected bucket 'test-bucket', got '%s'", unmarshaled.Input.Resource.Bucket)
	}
}

func TestPolicyResponse_JSON(t *testing.T) {
	// Test parsing true response
	trueJSON := `{"result": true}`
	var trueResponse PolicyResponse
	if err := json.Unmarshal([]byte(trueJSON), &trueResponse); err != nil {
		t.Fatalf("Failed to unmarshal true response: %v", err)
	}

	if !trueResponse.Result {
		t.Error("Expected result to be true")
	}

	// Test parsing false response
	falseJSON := `{"result": false}`
	var falseResponse PolicyResponse
	if err := json.Unmarshal([]byte(falseJSON), &falseResponse); err != nil {
		t.Fatalf("Failed to unmarshal false response: %v", err)
	}

	if falseResponse.Result {
		t.Error("Expected result to be false")
	}
}

func TestClient_Evaluate_Success_Allow(t *testing.T) {
	// Create a mock OPA server that returns allow=true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected application/json content type, got %s", r.Header.Get("Content-Type"))
		}

		if !strings.Contains(r.URL.Path, "/v1/data/meshx/authz/allow") {
			t.Errorf("Expected OPA policy path, got %s", r.URL.Path)
		}

		// Parse the request body
		var request PolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Failed to decode request: %v", err)
		}

		if request.Input.User != "alice" {
			t.Errorf("Expected user 'alice', got '%s'", request.Input.User)
		}

		// Return allow=true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PolicyResponse{Result: true})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
			Bucket:       "public-bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !allowed {
		t.Error("Expected policy to allow the request")
	}
}

func TestClient_Evaluate_Success_Deny(t *testing.T) {
	// Create a mock OPA server that returns allow=false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PolicyResponse{Result: false})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "bob",
		Action: "DELETE",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
			Bucket:       "restricted-bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if allowed {
		t.Error("Expected policy to deny the request")
	}
}

func TestClient_Evaluate_ServerError(t *testing.T) {
	// Create a mock OPA server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err == nil {
		t.Fatal("Expected error for 500 response")
	}

	if allowed {
		t.Error("Expected false result on error")
	}

	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("Expected error message to contain 'status 500', got: %v", err)
	}
}

func TestClient_Evaluate_BadResponse(t *testing.T) {
	// Create a mock OPA server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("invalid json"))
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err == nil {
		t.Fatal("Expected error for invalid JSON response")
	}

	if allowed {
		t.Error("Expected false result on error")
	}

	if !strings.Contains(err.Error(), "failed to decode") {
		t.Errorf("Expected decode error, got: %v", err)
	}
}

func TestClient_Evaluate_NetworkError(t *testing.T) {
	// Use an invalid URL to simulate network error
	client := NewClient("http://non-existent-opa-server:8181", 1*time.Millisecond)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err == nil {
		t.Fatal("Expected error for network failure")
	}

	if allowed {
		t.Error("Expected false result on error")
	}

	if !strings.Contains(err.Error(), "failed to send OPA request") {
		t.Errorf("Expected network error, got: %v", err)
	}
}

func TestClient_Evaluate_Timeout(t *testing.T) {
	// Create a slow server that exceeds timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(PolicyResponse{Result: true})
	}))
	defer server.Close()

	// Use very short timeout
	client := NewClient(server.URL, 1*time.Millisecond)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err == nil {
		t.Fatal("Expected timeout error")
	}

	if allowed {
		t.Error("Expected false result on timeout")
	}

	// The error should be about timeout or context cancellation
	if !strings.Contains(err.Error(), "failed to send OPA request") {
		t.Errorf("Expected request failure error, got: %v", err)
	}
}

func TestClient_Evaluate_ContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		json.NewEncoder(w).Encode(PolicyResponse{Result: true})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
		},
	}

	// Create context that gets cancelled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	allowed, err := client.Evaluate(ctx, input)
	if err == nil {
		t.Fatal("Expected context cancellation error")
	}

	if allowed {
		t.Error("Expected false result on context cancellation")
	}
}

func TestClient_Evaluate_ComplexResource(t *testing.T) {
	// Test with a complex resource that has all fields populated
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request PolicyRequest
		json.NewDecoder(r.Body).Decode(&request)

		// Verify all resource fields are present
		resource := request.Input.Resource
		if resource.ID != "res-123" {
			t.Errorf("Expected resource ID 'res-123', got '%s'", resource.ID)
		}
		if resource.Organization != "acme" {
			t.Errorf("Expected organization 'acme', got '%s'", resource.Organization)
		}
		if resource.Type != "object" {
			t.Errorf("Expected type 'object', got '%s'", resource.Type)
		}
		if resource.Bucket != "my-bucket" {
			t.Errorf("Expected bucket 'my-bucket', got '%s'", resource.Bucket)
		}
		if resource.Key != "path/to/file.txt" {
			t.Errorf("Expected key 'path/to/file.txt', got '%s'", resource.Key)
		}
		if len(resource.Tags) != 2 {
			t.Errorf("Expected 2 tags, got %d", len(resource.Tags))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PolicyResponse{Result: true})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			ID:           "res-123",
			Organization: "acme",
			Type:         "object",
			Bucket:       "my-bucket",
			Key:          "path/to/file.txt",
			Tags:         []string{"env:prod", "team:platform"},
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if !allowed {
		t.Error("Expected policy to allow the request")
	}
}

func TestClient_Evaluate_InvalidURL(t *testing.T) {
	// Test with invalid base URL
	client := NewClient("://invalid-url", 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
		},
	}

	ctx := context.Background()
	allowed, err := client.Evaluate(ctx, input)
	if err == nil {
		t.Fatal("Expected error for invalid URL")
	}

	if allowed {
		t.Error("Expected false result on error")
	}

	if !strings.Contains(err.Error(), "failed to create OPA request") {
		t.Errorf("Expected request creation error, got: %v", err)
	}
}

func BenchmarkClient_Evaluate(b *testing.B) {
	// Create a fast mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(PolicyResponse{Result: true})
	}))
	defer server.Close()

	client := NewClient(server.URL, 5*time.Second)
	
	input := Input{
		User:   "alice",
		Action: "READ",
		Resource: Resource{
			Organization: "acme",
			Type:         "bucket",
			Bucket:       "test-bucket",
		},
	}

	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := client.Evaluate(ctx, input)
			if err != nil {
				b.Fatalf("Evaluate failed: %v", err)
			}
		}
	})
}

func BenchmarkPolicyRequest_Marshal(b *testing.B) {
	request := PolicyRequest{
		Input: Input{
			User:   "alice",
			Action: "READ",
			Resource: Resource{
				ID:           "res-123",
				Organization: "acme",
				Type:         "object",
				Bucket:       "my-bucket",
				Key:          "path/to/file.txt",
				Tags:         []string{"env:prod", "team:platform"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(request)
		if err != nil {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}

func BenchmarkPolicyResponse_Unmarshal(b *testing.B) {
	jsonData := []byte(`{"result": true}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var response PolicyResponse
		err := json.Unmarshal(jsonData, &response)
		if err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}