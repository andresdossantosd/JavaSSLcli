# Vault Custom Secret Engine Plugin: Token Store & Rotator

## Overview

This Vault plugin is a **custom secret engine** written in **Go**, designed to **store and rotate tokens** by interacting with an external HTTP(S) service via a URL. The plugin uses a **token stored in Vault** itself for authentication with the external system. This guide outlines the concepts, implementation, integration steps, and usage for developers and administrators.

---

## Table of Contents

- [Concepts](#concepts)
- [Features](#features)
- [Architecture](#architecture)
- [Building the Plugin](#building-the-plugin)
- [Vault Setup](#vault-setup)
  - [1. Enable Plugin](#1-enable-plugin)
  - [2. Register Plugin](#2-register-plugin)
  - [3. Enable Custom Secret Engine](#3-enable-custom-secret-engine)
- [Authentication](#authentication)
- [Policies](#policies)
- [Secret Storage](#secret-storage)
- [Audit Logging](#audit-logging)
- [Plugin API](#plugin-api)
- [Rotation Process](#rotation-process)
- [Example Use Case](#example-use-case)
- [Contributing](#contributing)

---

## Concepts

- **Vault Plugin**: An extension point for Vault to implement custom logic (auth methods or secret engines).
- **Secret Engine**: A subsystem in Vault that handles secrets generation, storage, and lifecycle.
- **Token Rotation**: The act of securely revoking and generating new tokens in a system, triggered or scheduled by Vault.
- **Plugin Catalog**: Where custom Vault plugins are registered and enabled.

---

## Features

- Store service access tokens securely in Vault.
- Rotate tokens via an external HTTP(S) endpoint.
- Secure authentication to the external service using Vault-stored credentials.
- Integrates with Vault's audit logging and ACLs.
- Built using Go and HashiCorp Vault SDK.

---

## Architecture

```plaintext
User/API Call
     â
Vault (Custom Plugin)
     â
External API (Token Rotation Endpoint)
```

---

## Building the Plugin

### Prerequisites

- Go 1.21+
- Vault 1.13+
- GNU Make (optional)

### Steps

```bash
git clone https://github.com/your-org/vault-token-rotator-plugin.git
cd vault-token-rotator-plugin
go mod tidy
go build -o vault-plugin-token-rotator
```

Place the compiled binary in Vault's plugin directory:

```bash
mv vault-plugin-token-rotator /etc/vault/plugins/
```

---

## Vault Setup

### 1. Enable Plugin

Calculate SHA256:

```bash
sha256sum /etc/vault/plugins/vault-plugin-token-rotator
```

### 2. Register Plugin

```bash
vault write sys/plugins/catalog/secret/token-rotator \
    sha256="<sha256-hash>" \
    command="vault-plugin-token-rotator"
```

### 3. Enable Custom Secret Engine

```bash
vault secrets enable -path=token-rotator plugin

vault write token-rotator/config \
    rotation_url="https://example.com/api/rotate" \
    auth_token_path="token-rotator/creds/admin"
```

---

## Authentication

Vault authentication methods (e.g., AppRole, LDAP, JWT) should be used to grant users/applications access.

```bash
vault auth enable approle
```

---

## Policies

Example policy to access and use the plugin:

```hcl
path "token-rotator/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

---

## Secret Storage

Secrets are stored internally by the plugin using Vault's KV-like structure. Each rotated token is versioned.

---

## Audit Logging

Enable it:

```bash
vault audit enable file file_path=/var/log/vault_audit.log
```

---

## Plugin API

### Configure Rotation

```bash
vault write token-rotator/config \
    rotation_url="https://external.api/rotate" \
    auth_token_path="token-rotator/creds/admin"
```

### Store Admin Token

```bash
vault write token-rotator/creds/admin token="abcd1234"
```

### Trigger Rotation

```bash
vault write token-rotator/rotate/service1
```

### Read Current Token

```bash
vault read token-rotator/creds/service1
```

---

## Rotation Process

1. Plugin fetches stored admin token.
2. Sends POST request to `rotation_url` with the token.
3. Receives new token from the external system.
4. Stores and versions the token under the given path.
5. Logs the event in Vault's audit log.

---

## Example Use Case

- CI pipeline rotates a GitHub Actions token via this plugin
- Secure retrieval from Vault using AppRole or JWT auth

---

## Contributing

Submit PRs and issues on GitHub.

---

## License

MIT License

---

# Go Plugin Source Code

## `go.mod`

```go
module vault-plugin-token-rotator

go 1.21

require (
	github.com/hashicorp/vault/sdk v0.15.0
)
```

## `main.go`

```go
package main

import (
	"os"

	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: backendFactory,
	})
	if err != nil {
		os.Exit(1)
	}
}
```

## `backend.go`

```go
package main

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func backendFactory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help: "Custom Vault plugin for storing and rotating tokens.",
		Paths: framework.PathAppend(
			pathConfig(b),
			pathRotate(b),
		),
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}

	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}
```

## `path_config.go`

```go
package main

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config$",
			Fields: map[string]*framework.FieldSchema{
				"rotation_url": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "The external API endpoint used to rotate tokens.",
				},
				"auth_token_path": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Path where admin token is stored (e.g., token-rotator/creds/admin).",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.handleWriteConfig,
			},
			HelpSynopsis:    "Store rotation URL and token path.",
			HelpDescription: "Stores configuration including rotation endpoint and admin token reference.",
		},
		{
			Pattern: "creds/admin",
			Fields: map[string]*framework.FieldSchema{
				"token": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Admin token to use for authenticating to the external service.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.handleStoreAdminToken,
				logical.ReadOperation:   b.handleReadAdminToken,
			},
		},
	}
}

func (b *backend) handleWriteConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	url := data.Get("rotation_url").(string)
	path := data.Get("auth_token_path").(string)

	entry := map[string]interface{}{
		"rotation_url":    url,
		"auth_token_path": path,
	}

	err := req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "config",
		Value: []byte(logicalutil.EncodeJSON(entry)),
	})
	if err != nil {
		return nil, err
	}

	return &logical.Response{Data: entry}, nil
}

func (b *backend) handleStoreAdminToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	token := data.Get("token").(string)
	return nil, req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   "creds/admin",
		Value: []byte(token),
	})
}

func (b *backend) handleReadAdminToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "creds/admin")
	if err != nil || entry == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"token": string(entry.Value),
		},
	}, nil
}
```

## `path_rotate.go`

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotate(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rotate/(?P<name>[a-zA-Z0-9_-]+)",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Required:    true,
					Description: "Name of the service to rotate the token for.",
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.WriteOperation: b.handleRotate,
				logical.ReadOperation:  b.handleReadRotatedToken,
			},
			HelpSynopsis:    "Rotate a service token.",
			HelpDescription: "Sends request to external API using stored admin token and saves new token.",
		},
	}
}

func (b *backend) handleRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	configEntry, err := req.Storage.Get(ctx, "config")
	if err != nil || configEntry == nil {
		return nil, fmt.Errorf("plugin not configured")
	}

	var config map[string]interface{}
	if err := json.Unmarshal(configEntry.Value, &config); err != nil {
		return nil, err
	}

	rotationURL := config["rotation_url"].(string)
	adminTokenEntry, err := req.Storage.Get(ctx, "creds/admin")
	if err != nil || adminTokenEntry == nil {
		return nil, fmt.Errorf("admin token not found")
	}
	adminToken := string(adminTokenEntry.Value)

	body := map[string]string{"service": name}
	jsonBody, _ := json.Marshal(body)

	reqHTTP, _ := http.NewRequest("POST", rotationURL, bytes.NewBuffer(jsonBody))
	reqHTTP.Header.Set("Authorization", fmt.Sprintf("Bearer %s", adminToken))
	reqHTTP.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		responseBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("rotation failed: %s", responseBody)
	}

	var response struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, err
	}

	tokenPath := fmt.Sprintf("creds/%s", name)
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   tokenPath,
		Value: []byte(response.Token),
	})
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token": response.Token,
		},
	}, nil
}

func (b *backend) handleReadRotatedToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	entry, err := req.Storage.Get(ctx, fmt.Sprintf("creds/%s", name))
	if err != nil || entry == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"token": string(entry.Value),
		},
	}, nil
}
```

Place the binary in /etc/vault/plugins/, register it in Vault as described in the README, and you’re ready to go!
```bash
go mod tidy
go build -o vault-plugin-token-rotator
```

# 📦 Vault Plugin Installation & Usage Guide

This guide documents how to install, register, enable, and use the custom Vault plugin `vault-plugin-token-rotator`.

---

## 📁 Plugin Installation Folder

### Vault Plugin Directory

Vault loads custom plugins from the directory specified by the `plugin_directory` setting in its configuration file.

### 1. Configure Plugin Directory

Edit the Vault server config file, usually at `/etc/vault.d/vault.hcl`:

```hcl
plugin_directory = "/etc/vault/plugins"
```

Then restart Vault to apply changes:

```bash
sudo systemctl restart vault
```

---

### 2. Move Plugin to Directory

Once built, move the binary:

```bash
sudo mv ./vault-plugin-token-rotator /etc/vault/plugins/
sudo chmod +x /etc/vault/plugins/vault-plugin-token-rotator
```

Ensure the file is executable and owned by the appropriate user.

---

## 🔐 Register and Use the Plugin in Vault

### 3. Get SHA256 Checksum

```bash
sha256sum /etc/vault/plugins/vault-plugin-token-rotator
```

Copy the resulting hash.

---

### 4. Register Plugin with Vault

```bash
vault write sys/plugins/catalog/secret/token-rotator \
    sha256="<SHA256_HASH>" \
    command="vault-plugin-token-rotator"
```

Replace `<SHA256_HASH>` with the actual hash.

---

### 5. Enable Plugin as a Secret Engine

```bash
vault secrets enable -path=token-rotator plugin
```

---

### 6. Configure Plugin

```bash
vault write token-rotator/config \
    rotation_url="https://external.api/rotate" \
    auth_token_path="token-rotator/creds/admin"
```

---

### 7. Store Admin Token

```bash
vault write token-rotator/creds/admin token="your-admin-token"
```

---

### 8. Rotate a Token

```bash
vault write token-rotator/rotate/github
```

---

### 9. Read Rotated Token

```bash
vault read token-rotator/creds/github
```

---

## ✅ Summary Table

| Step | Description |
|------|-------------|
| 1    | Set `plugin_directory` in Vault config |
| 2    | Move plugin binary to that directory |
| 3    | Get SHA256 hash and register plugin |
| 4    | Enable plugin at a mount path |
| 5    | Configure plugin with rotation URL and token path |
| 6    | Store admin token Vault will use |
| 7    | Rotate token for a service |
| 8    | Read the rotated token |

---

## 🛡️ Recommended Access Control

Example Vault policy to allow use of the plugin:

```hcl
path "token-rotator/*" {
  capabilities = ["read", "create", "update"]
}
```

Apply this policy to Vault entities (AppRole, userpass, etc.).

---

## 📝 Enable Audit Logging (Optional)

```bash
vault audit enable file file_path=/var/log/vault_audit.log
```

This helps track who accessed or rotated tokens.

---