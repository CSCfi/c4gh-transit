package c4ghtransit

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	whitelistStoragePath = "whitelist"
)

type transitWhitelistEntry struct {
	Key     string `json:"key"`
	Flavor  string `json:"flavor"`
	Service string `json:"service"`
	Project string `json:"project"`
}

// pathWhitelist extends the Vault API with a "/whitelist"
// endpoint for adding whitelisted public keys for transit.
func (b *c4ghTransitBackend) pathWhitelist() *framework.Path {
	return &framework.Path{
		Pattern: "whitelist/" + framework.GenericNameRegex("name") + "/" + framework.GenericNameRegex("service"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the whitelisted key",
				Required:    true,
			},
			"service": {
				Type:        framework.TypeString,
				Description: "Identifier or name for the whitelisted service or user",
			},
			"flavor": {
				Type:        framework.TypeString,
				Description: "Public key flavor",
				Required:    true,
			},
			"pubkey": {
				Type:        framework.TypeString,
				Description: "Public key to be whitelisted",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathWhitelistRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathWhitelistWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathWhitelistWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathWhitelistDelete,
			},
		},
		HelpSynopsis:    pathWhitelistHelpSynopsis,
		HelpDescription: pathWhitelistHelpDescription,
	}
}

func (b *c4ghTransitBackend) pathWhitelistList() *framework.Path {
	return &framework.Path{
		Pattern: "whitelist/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListWhitelist,
			},
		},
		HelpSynopsis:    pathWhitelistListHelpSynopsis,
		HelpDescription: pathWhitelistListHelpDescription,
	}
}

// List whitelisted keys in Vault storage
func (b *c4ghTransitBackend) pathListWhitelist(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "whitelist/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// Read a public key from Vault storage
func (b *c4ghTransitBackend) pathWhitelistRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	name := d.Get("name").(string)
	service := d.Get("service").(string)
	entry, err := req.Storage.Get(ctx, "whitelist/"+name+"/"+service)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result transitWhitelistEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key":     result.Key,
			"flavor":  result.Flavor,
			"service": result.Service,
			"project": result.Project,
		},
	}, nil
}

// Write a public key into Vault storage
func (b *c4ghTransitBackend) pathWhitelistWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	name := d.Get("name").(string)
	pubkey := d.Get("pubkey").(string)
	flavor := d.Get("flavor").(string)
	service := d.Get("service").(string)

	switch strings.ToLower(flavor) {
	case "crypt4gh":
		return logical.ErrorResponse("Crypt4gh native keys not yet supported."), nil
	case "ed25519":
	default:
		return logical.ErrorResponse("Key flavor not supported."), nil
	}

	if pubkey == "" {
		return logical.ErrorResponse("Missing public key"), nil
	}

	if service == "" {
		return logical.ErrorResponse("Service that owns the key needs to be specified."), nil
	}

	keyPath := fmt.Sprintf("whitelist/%s/%s", name, service)

	entry, err := logical.StorageEntryJSON(keyPath, map[string]interface{}{
		"key":     pubkey,
		"flavor":  flavor,
		"service": service,
		"project": name,
	})

	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

// Delete a public key from Vault storage
func (b *c4ghTransitBackend) pathWhitelistDelete(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	name := d.Get("name").(string)
	service := d.Get("service").(string)
	keyPath := fmt.Sprintf("whitelist/%s/%s", name, service)

	err := req.Storage.Delete(ctx, keyPath)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

const (
	pathWhitelistHelpSynopsis    = `Manages the vault keys whitelisted for c4gh-transit downloads`
	pathWhitelistHelpDescription = `
This path allows you to whitelist public keys to re-encrypt for with c4gh-transit
plugin. The whitelisted public key can be specified in the pubkey field.
`
	pathWhitelistListHelpSynopsis    = `List the whitelisted keys for c4gh-transit`
	pathWhitelistListHelpDescription = `Whitelisted key order is not specified`
)
