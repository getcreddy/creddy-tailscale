//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

func getTestConfig(t *testing.T) string {
	apiKey := os.Getenv("TAILSCALE_API_KEY")
	if apiKey == "" {
		t.Skip("TAILSCALE_API_KEY not set, skipping integration tests")
	}

	tailnet := os.Getenv("TAILSCALE_TAILNET")
	if tailnet == "" {
		t.Skip("TAILSCALE_TAILNET not set, skipping integration tests")
	}

	return fmt.Sprintf(`{
		"api_key": "%s",
		"tailnet": "%s",
		"default_tags": ["tag:creddy-test"],
		"ephemeral": true,
		"preauthorized": true
	}`, apiKey, tailnet)
}

func TestIntegration_PluginInfo(t *testing.T) {
	plugin := NewPlugin()
	info, err := plugin.Info(context.Background())
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.Name != "tailscale" {
		t.Errorf("expected name 'tailscale', got %q", info.Name)
	}
	t.Logf("Plugin: %s v%s", info.Name, info.Version)
}

func TestIntegration_Configure(t *testing.T) {
	config := getTestConfig(t)
	plugin := NewPlugin()
	
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}
}

func TestIntegration_Validate(t *testing.T) {
	config := getTestConfig(t)
	plugin := NewPlugin()
	
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	err = plugin.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	t.Log("API key validated ✓")
}

func TestIntegration_FullLifecycle(t *testing.T) {
	config := getTestConfig(t)
	plugin := NewPlugin()
	
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	err = plugin.Validate(context.Background())
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}

	// Create an auth key
	cred, err := plugin.GetCredential(context.Background(), &sdk.CredentialRequest{
		Scope: "tailscale",
		TTL:   5 * time.Minute,
		Agent: sdk.Agent{
			ID:   "integration-test",
			Name: "integration-test",
		},
	})
	if err != nil {
		t.Fatalf("GetCredential() error: %v", err)
	}

	// Validate credential fields
	if cred.Value == "" {
		t.Fatal("expected credential value (auth key)")
	}
	if !strings.HasPrefix(cred.Value, "tskey-auth-") {
		t.Errorf("expected auth key to start with 'tskey-auth-', got: %s...", cred.Value[:20])
	}
	if cred.ExternalID == "" {
		t.Fatal("expected external ID (key ID)")
	}
	if cred.ExpiresAt.IsZero() {
		t.Fatal("expected expiration time")
	}

	t.Logf("Created auth key: %s... (expires: %v)", cred.Value[:25], cred.ExpiresAt)

	// Revoke the key
	err = plugin.RevokeCredential(context.Background(), cred.ExternalID)
	if err != nil {
		t.Fatalf("RevokeCredential() error: %v", err)
	}
	t.Log("Revoked auth key ✓")

	// Revoking again should be idempotent
	err = plugin.RevokeCredential(context.Background(), cred.ExternalID)
	if err != nil {
		t.Fatalf("Second revoke should be idempotent: %v", err)
	}
	t.Log("Second revoke idempotent ✓")
}

func TestIntegration_WithTags(t *testing.T) {
	config := getTestConfig(t)
	plugin := NewPlugin()
	
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	// Create an auth key with specific tag
	cred, err := plugin.GetCredential(context.Background(), &sdk.CredentialRequest{
		Scope: "tailscale:tag:creddy-test",
		TTL:   5 * time.Minute,
		Agent: sdk.Agent{
			ID:   "tag-test",
			Name: "tag-test",
		},
	})
	if err != nil {
		t.Fatalf("GetCredential() error: %v", err)
	}

	if cred.Metadata["tags"] != "tag:creddy-test" {
		t.Errorf("expected tags 'tag:creddy-test', got %q", cred.Metadata["tags"])
	}

	t.Logf("Created tagged auth key: %s...", cred.Value[:25])

	// Clean up
	plugin.RevokeCredential(context.Background(), cred.ExternalID)
}

func TestIntegration_TTLRespected(t *testing.T) {
	config := getTestConfig(t)
	plugin := NewPlugin()
	
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	ttl := 10 * time.Minute
	before := time.Now()

	cred, err := plugin.GetCredential(context.Background(), &sdk.CredentialRequest{
		Scope: "tailscale",
		TTL:   ttl,
		Agent: sdk.Agent{
			ID:   "ttl-test",
			Name: "ttl-test",
		},
	})
	if err != nil {
		t.Fatalf("GetCredential() error: %v", err)
	}
	defer plugin.RevokeCredential(context.Background(), cred.ExternalID)

	// Verify expiration is approximately now + TTL
	expectedExpiry := before.Add(ttl)
	diff := cred.ExpiresAt.Sub(expectedExpiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("ExpiresAt off by too much: expected ~%v, got %v", expectedExpiry, cred.ExpiresAt)
	}

	t.Logf("TTL respected: expires in ~%v", time.Until(cred.ExpiresAt).Round(time.Second))
}

func TestIntegration_InvalidAPIKey(t *testing.T) {
	plugin := NewPlugin()
	
	config := `{
		"api_key": "tskey-api-invalid-key",
		"tailnet": "example.com"
	}`
	
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	err = plugin.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for invalid API key")
	}
	t.Logf("Invalid API key correctly rejected: %v", err)
}
