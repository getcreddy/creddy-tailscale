package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

func TestPluginInfo(t *testing.T) {
	plugin := NewPlugin()
	info, err := plugin.Info(context.Background())
	if err != nil {
		t.Fatalf("Info() error: %v", err)
	}

	if info.Name != "tailscale" {
		t.Errorf("expected name 'tailscale', got %q", info.Name)
	}
	if info.Version == "" {
		t.Error("expected non-empty version")
	}
}

func TestConfigSchema(t *testing.T) {
	plugin := NewPlugin()
	schema, err := plugin.ConfigSchema(context.Background())
	if err != nil {
		t.Fatalf("ConfigSchema() error: %v", err)
	}

	if len(schema) == 0 {
		t.Fatal("expected non-empty schema")
	}

	// Check required fields
	requiredFields := map[string]bool{"api_key": false, "tailnet": false}
	for _, field := range schema {
		if _, ok := requiredFields[field.Name]; ok {
			requiredFields[field.Name] = true
			if !field.Required {
				t.Errorf("%s should be required", field.Name)
			}
		}
	}
	for name, found := range requiredFields {
		if !found {
			t.Errorf("missing required field: %s", name)
		}
	}
}

func TestConfigure_Valid(t *testing.T) {
	plugin := NewPlugin()
	config := `{"api_key": "tskey-api-xxx", "tailnet": "mycompany.com"}`
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	if plugin.config.APIKey != "tskey-api-xxx" {
		t.Errorf("expected api_key 'tskey-api-xxx', got %q", plugin.config.APIKey)
	}
	if plugin.config.Tailnet != "mycompany.com" {
		t.Errorf("expected tailnet 'mycompany.com', got %q", plugin.config.Tailnet)
	}
}

func TestConfigure_MissingAPIKey(t *testing.T) {
	plugin := NewPlugin()
	config := `{"tailnet": "mycompany.com"}`
	err := plugin.Configure(context.Background(), config)
	if err == nil {
		t.Fatal("expected error for missing api_key")
	}
}

func TestConfigure_MissingTailnet(t *testing.T) {
	plugin := NewPlugin()
	config := `{"api_key": "tskey-api-xxx"}`
	err := plugin.Configure(context.Background(), config)
	if err == nil {
		t.Fatal("expected error for missing tailnet")
	}
}

func TestConfigure_InvalidJSON(t *testing.T) {
	plugin := NewPlugin()
	err := plugin.Configure(context.Background(), `{invalid}`)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestConfigure_WithOptions(t *testing.T) {
	plugin := NewPlugin()
	config := `{
		"api_key": "tskey-api-xxx",
		"tailnet": "mycompany.com",
		"default_tags": ["tag:ci", "tag:ephemeral"],
		"ephemeral": true,
		"preauthorized": true
	}`
	err := plugin.Configure(context.Background(), config)
	if err != nil {
		t.Fatalf("Configure() error: %v", err)
	}

	if len(plugin.config.DefaultTags) != 2 {
		t.Errorf("expected 2 tags, got %d", len(plugin.config.DefaultTags))
	}
	if !plugin.config.Ephemeral {
		t.Error("expected ephemeral=true")
	}
	if !plugin.config.Preauthorized {
		t.Error("expected preauthorized=true")
	}
}

func TestMatchScope(t *testing.T) {
	plugin := NewPlugin()

	tests := []struct {
		scope string
		want  bool
	}{
		{"tailscale", true},
		{"tailscale:tag:ci", true},
		{"tailscale:tag:agent", true},
		{"tailscale:admin", true},
		{"github", false},
		{"anthropic", false},
	}

	for _, tt := range tests {
		t.Run(tt.scope, func(t *testing.T) {
			got, err := plugin.MatchScope(context.Background(), tt.scope)
			if err != nil {
				t.Fatalf("MatchScope() error: %v", err)
			}
			if got != tt.want {
				t.Errorf("MatchScope(%q) = %v, want %v", tt.scope, got, tt.want)
			}
		})
	}
}

func TestScopes(t *testing.T) {
	plugin := NewPlugin()
	scopes, err := plugin.Scopes(context.Background())
	if err != nil {
		t.Fatalf("Scopes() error: %v", err)
	}

	if len(scopes) == 0 {
		t.Fatal("expected at least one scope")
	}

	hasTailscale := false
	for _, s := range scopes {
		if s.Pattern == "tailscale" {
			hasTailscale = true
		}
	}
	if !hasTailscale {
		t.Error("expected 'tailscale' scope")
	}
}

func TestConstraints(t *testing.T) {
	plugin := NewPlugin()
	constraints, err := plugin.Constraints(context.Background())
	if err != nil {
		t.Fatalf("Constraints() error: %v", err)
	}

	if constraints.MinTTL <= 0 {
		t.Error("expected positive MinTTL")
	}
	if constraints.MaxTTL <= constraints.MinTTL {
		t.Error("expected MaxTTL > MinTTL")
	}
}

func TestValidate_NotConfigured(t *testing.T) {
	plugin := NewPlugin()
	err := plugin.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error when not configured")
	}
}

func TestGetCredential_NotConfigured(t *testing.T) {
	plugin := NewPlugin()
	_, err := plugin.GetCredential(context.Background(), &sdk.CredentialRequest{
		Scope: "tailscale",
		TTL:   10 * time.Minute,
	})
	if err == nil {
		t.Fatal("expected error when not configured")
	}
}

func TestRevokeCredential_NotConfigured(t *testing.T) {
	plugin := NewPlugin()
	// Should not error when not configured
	err := plugin.RevokeCredential(context.Background(), "some-key-id")
	if err != nil {
		t.Fatalf("RevokeCredential() should not error when not configured: %v", err)
	}
}

func TestConfig_JSON(t *testing.T) {
	cfg := &TailscaleConfig{
		APIKey:        "tskey-api-xxx",
		Tailnet:       "mycompany.com",
		DefaultTags:   []string{"tag:ci"},
		Ephemeral:     true,
		Preauthorized: true,
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded TailscaleConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.APIKey != cfg.APIKey {
		t.Error("APIKey mismatch")
	}
	if decoded.Tailnet != cfg.Tailnet {
		t.Error("Tailnet mismatch")
	}
}
