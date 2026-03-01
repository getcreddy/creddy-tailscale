# creddy-tailscale

Creddy plugin for ephemeral Tailscale auth keys.

Agents request `creddy get tailscale` and receive a single-use, ephemeral auth key to join your tailnet. When the agent disconnects, the device is automatically removed.

## Installation

```bash
creddy plugin install tailscale
```

## Setup

Add the backend with your Tailscale API key:

```bash
creddy backend add tailscale
```

You'll be prompted for:
- **api_key**: Tailscale API key (from admin console → Settings → Keys → Generate API Key)
- **tailnet**: Your tailnet name (e.g., `mycompany.com` or organization name)

### Configuration Options

```json
{
  "api_key": "tskey-api-xxx",
  "tailnet": "mycompany.com",
  "default_tags": ["tag:agent"],
  "ephemeral": true,
  "preauthorized": true
}
```

- **default_tags**: ACL tags applied to all devices joining via these keys
- **ephemeral**: Devices auto-removed when they disconnect (recommended)
- **preauthorized**: Devices don't require manual approval in admin console

## Usage

### Basic

```bash
# Get an auth key
AUTH_KEY=$(creddy get tailscale)

# Join the tailnet
tailscale up --auth-key=$AUTH_KEY
```

### With Specific Tags

```bash
# Request a key with specific ACL tag
AUTH_KEY=$(creddy get tailscale --scope tailscale:tag:ci)
tailscale up --auth-key=$AUTH_KEY
```

### In CI/CD

```yaml
# GitHub Actions example
jobs:
  deploy:
    steps:
      - name: Join tailnet
        run: |
          AUTH_KEY=$(creddy get tailscale --ttl 30m)
          sudo tailscale up --auth-key=$AUTH_KEY
          
      - name: Access internal services
        run: |
          curl http://internal-api.ts.net/deploy
```

## Scopes

- `tailscale` — Create ephemeral auth keys with default tags
- `tailscale:tag:*` — Create keys with specific ACL tags (e.g., `tailscale:tag:ci`)

## Security

- Auth keys are single-use (can only join one device)
- Devices are ephemeral (removed when they disconnect)
- Keys have TTL (expire even if not used)
- ACL tags control what the device can access

## ACL Example

```json
{
  "acls": [
    // CI agents can only access internal APIs
    {"action": "accept", "src": ["tag:ci"], "dst": ["tag:api:*"]},
    
    // Production agents have broader access
    {"action": "accept", "src": ["tag:prod-agent"], "dst": ["*:*"]}
  ],
  "tagOwners": {
    "tag:ci": ["group:devops"],
    "tag:prod-agent": ["group:sre"]
  }
}
```

## Development

```bash
# Run unit tests
make test

# Run integration tests (requires TAILSCALE_API_KEY and TAILSCALE_TAILNET)
export TAILSCALE_API_KEY=tskey-api-xxx
export TAILSCALE_TAILNET=mycompany.com
make test-integration

# Build
make build

# Install locally
make install
```

## License

MIT
