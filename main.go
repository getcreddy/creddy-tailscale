package main

import (
	"fmt"
	"os"

	sdk "github.com/getcreddy/creddy-plugin-sdk"
)

func main() {
	// Handle CLI commands
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "info":
			fmt.Printf("Name:              %s\n", PluginName)
			fmt.Printf("Version:           %s\n", PluginVersion)
			fmt.Printf("Description:       Ephemeral Tailscale auth keys for joining tailnets\n")
			fmt.Printf("Min Creddy Version: 0.4.0\n")
			return

		case "scopes":
			fmt.Println("Pattern: tailscale")
			fmt.Println("  Description: Create ephemeral auth keys to join tailnet")
			fmt.Println("  Examples:")
			fmt.Println("    - tailscale")
			fmt.Println()
			fmt.Println("Pattern: tailscale:tag:*")
			fmt.Println("  Description: Create auth keys with specific ACL tags")
			fmt.Println("  Examples:")
			fmt.Println("    - tailscale:tag:ci")
			fmt.Println("    - tailscale:tag:agent")
			return

		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	// Default: run as Creddy plugin
	sdk.Serve(NewPlugin())
}

func printHelp() {
	fmt.Println("creddy-tailscale - Tailscale plugin for Creddy")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  info     Show plugin information")
	fmt.Println("  scopes   List supported scopes")
	fmt.Println("  help     Show this help")
	fmt.Println()
	fmt.Println("Setup:")
	fmt.Println("  1. Add backend to Creddy:")
	fmt.Println("     creddy backend add tailscale --config '{")
	fmt.Println("       \"api_key\": \"tskey-api-...\",")
	fmt.Println("       \"tailnet\": \"mycompany.com\",")
	fmt.Println("       \"default_tags\": [\"tag:agent\"],")
	fmt.Println("       \"ephemeral\": true,")
	fmt.Println("       \"preauthorized\": true")
	fmt.Println("     }'")
	fmt.Println()
	fmt.Println("  2. Agent gets an auth key:")
	fmt.Println("     AUTH_KEY=$(creddy get tailscale)")
	fmt.Println()
	fmt.Println("  3. Agent joins tailnet:")
	fmt.Println("     tailscale up --auth-key=$AUTH_KEY")
}
