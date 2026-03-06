package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

const (
	PluginName       = "tailscale"
	tailscaleAPIBase = "https://api.tailscale.com/api/v2"
)

var PluginVersion = "dev"

type TailscalePlugin struct {
	config *TailscaleConfig
}

type TailscaleConfig struct {
	APIKey        string   `json:"api_key"`
	Tailnet       string   `json:"tailnet"`
	DefaultTags   []string `json:"default_tags"`
	Ephemeral     bool     `json:"ephemeral"`
	Preauthorized bool     `json:"preauthorized"`
}

func NewPlugin() *TailscalePlugin {
	return &TailscalePlugin{}
}

func (p *TailscalePlugin) Info(ctx context.Context) (*sdk.PluginInfo, error) {
	return &sdk.PluginInfo{
		Name:             PluginName,
		Version:          PluginVersion,
		Description:      "Ephemeral Tailscale auth keys for joining tailnets",
		MinCreddyVersion: "0.4.0",
	}, nil
}

func (p *TailscalePlugin) ConfigSchema(ctx context.Context) ([]sdk.ConfigField, error) {
	return []sdk.ConfigField{
		{
			Name:        "api_key",
			Type:        "secret",
			Description: "Tailscale API key (tskey-api-..., NOT auth key). Generate at: Settings → Keys → Generate API Key",
			Required:    true,
		},
		{
			Name:        "tailnet",
			Type:        "string",
			Description: "Tailnet name (e.g., 'mycompany.com' or org name)",
			Required:    true,
		},
		{
			Name:        "default_tags",
			Type:        "array",
			Description: "Default ACL tags for auth keys (e.g., 'tag:agent')",
			Required:    false,
		},
		{
			Name:        "ephemeral",
			Type:        "bool",
			Description: "Create ephemeral devices (auto-removed on disconnect)",
			Required:    false,
			Default:     "true",
		},
		{
			Name:        "preauthorized",
			Type:        "bool",
			Description: "Pre-authorize devices (no manual approval needed)",
			Required:    false,
			Default:     "true",
		},
	}, nil
}

func (p *TailscalePlugin) Configure(ctx context.Context, configJSON string) error {
	var config TailscaleConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}

	if config.APIKey == "" {
		return fmt.Errorf("api_key is required")
	}

	// Validate key type - must be an API key, not an auth key
	if strings.HasPrefix(config.APIKey, "tskey-auth-") {
		return fmt.Errorf("invalid key type: got auth key (tskey-auth-...), need API key (tskey-api-...). Generate an API key in Tailscale admin console → Settings → Keys")
	}
	if !strings.HasPrefix(config.APIKey, "tskey-api-") {
		return fmt.Errorf("invalid API key format: expected key starting with 'tskey-api-'")
	}

	if config.Tailnet == "" {
		return fmt.Errorf("tailnet is required")
	}

	p.config = &config
	return nil
}

func (p *TailscalePlugin) Validate(ctx context.Context) error {
	if p.config == nil {
		return fmt.Errorf("not configured")
	}

	// Verify API key works by fetching tailnet info
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("%s/tailnet/%s/keys", tailscaleAPIBase, p.config.Tailnet), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to Tailscale API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("invalid API key")
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("tailnet not found: %s", p.config.Tailnet)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API error: %s", string(body))
	}

	return nil
}

func (p *TailscalePlugin) Scopes(ctx context.Context) ([]sdk.ScopeSpec, error) {
	return []sdk.ScopeSpec{
		{
			Pattern:     "tailscale",
			Description: "Create ephemeral auth keys to join tailnet",
			Examples:    []string{"tailscale"},
		},
		{
			Pattern:     "tailscale:tag:*",
			Description: "Create auth keys with specific ACL tags",
			Examples:    []string{"tailscale:tag:ci", "tailscale:tag:agent"},
		},
	}, nil
}

func (p *TailscalePlugin) MatchScope(ctx context.Context, scope string) (bool, error) {
	if scope == "tailscale" {
		return true, nil
	}
	if strings.HasPrefix(scope, "tailscale:") {
		return true, nil
	}
	return false, nil
}

func (p *TailscalePlugin) Constraints(ctx context.Context) (*sdk.Constraints, error) {
	return &sdk.Constraints{
		MinTTL: 1 * time.Minute,
		MaxTTL: 24 * time.Hour, // Tailscale keys can be longer, but we cap it
	}, nil
}

func (p *TailscalePlugin) GetCredential(ctx context.Context, req *sdk.CredentialRequest) (*sdk.Credential, error) {
	if p.config == nil {
		return nil, fmt.Errorf("not configured")
	}

	// Parse scope for tags
	tags := p.config.DefaultTags
	if strings.HasPrefix(req.Scope, "tailscale:tag:") {
		tag := strings.TrimPrefix(req.Scope, "tailscale:tag:")
		if !strings.HasPrefix(tag, "tag:") {
			tag = "tag:" + tag
		}
		tags = []string{tag}
	}

	// Calculate expiry
	expiresAt := time.Now().Add(req.TTL)

	// Create auth key via Tailscale API
	authKey, keyID, err := p.createAuthKey(ctx, tags, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth key: %w", err)
	}

	return &sdk.Credential{
		Value:      authKey,
		Credential: keyID,
		ExpiresAt:  expiresAt,
		Metadata: map[string]string{
			"tailnet":   p.config.Tailnet,
			"ephemeral": fmt.Sprintf("%v", p.config.Ephemeral),
			"tags":      strings.Join(tags, ","),
		},
	}, nil
}

func (p *TailscalePlugin) RevokeCredential(ctx context.Context, externalID string) error {
	if p.config == nil {
		return nil // Not configured, nothing to do
	}

	// Delete the auth key
	req, err := http.NewRequestWithContext(ctx, "DELETE",
		fmt.Sprintf("%s/tailnet/%s/keys/%s", tailscaleAPIBase, p.config.Tailnet, externalID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// 404 is fine - key already deleted or expired
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to revoke key: %s", string(body))
	}

	return nil
}

// createAuthKey creates a new auth key via Tailscale API
func (p *TailscalePlugin) createAuthKey(ctx context.Context, tags []string, expiresAt time.Time) (string, string, error) {
	payload := map[string]interface{}{
		"capabilities": map[string]interface{}{
			"devices": map[string]interface{}{
				"create": map[string]interface{}{
					"reusable":      false,
					"ephemeral":     p.config.Ephemeral,
					"preauthorized": p.config.Preauthorized,
					"tags":          tags,
				},
			},
		},
		"expirySeconds": int(time.Until(expiresAt).Seconds()),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/tailnet/%s/keys", tailscaleAPIBase, p.config.Tailnet),
		bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", "", fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Key, result.ID, nil
}
