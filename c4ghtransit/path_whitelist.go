package c4ghtransit

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/neicnordic/crypt4gh/keys"
	"golang.org/x/crypto/chacha20poly1305"
)

type transitWhitelistEntry struct {
	Key     string `json:"key"`
	Flavor  string `json:"flavor"`
	Service string `json:"service"`
	Project string `json:"project"`
	Name    string `json:"name"`
}

// pathWhitelist extends the Vault API with a "/whitelist"
// endpoint for adding whitelisted public keys for transit.
func (b *C4ghBackend) pathWhitelist() *framework.Path {
	return &framework.Path{
		Pattern: "whitelist/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("service") + "/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project whitelisted key has access to",
				Required:    true,
			},
			"service": {
				Type:        framework.TypeNameString,
				Description: "Identifier or name for the whitelisted service or user",
				Required:    true,
			},
			"name": {
				Type:        framework.TypeNameString,
				Description: "Name of the whitelisted key",
				Required:    true,
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
		ExistenceCheck:  b.pathWhitelistExistenceCheck,
		HelpSynopsis:    pathWhitelistHelpSynopsis,
		HelpDescription: pathWhitelistHelpDescription,
	}
}

func (b *C4ghBackend) pathListServices() *framework.Path {
	return &framework.Path{
		Pattern: "whitelist/" + framework.GenericNameRegex("project") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the key is uploaded for",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathServicesList,
			},
		},
		HelpSynopsis:    pathServicesListHelpSynopsis,
		HelpDescription: pathServicesListHelpDescription,
	}
}

func (b *C4ghBackend) pathListWhitelistedKeys() *framework.Path {
	return &framework.Path{
		Pattern: "whitelist/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("service") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the key is uploaded for",
				Required:    true,
			},
			"service": {
				Type:        framework.TypeNameString,
				Description: "Identifier or name for the whitelisted service or user",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathWhitelistedKeysList,
			},
		},
		HelpSynopsis:    pathWhitelistedKeysListHelpSynopsis,
		HelpDescription: pathWhitelistedKeysListHelpDescription,
	}
}

// List whitelisted keys in Vault storage
func (b *C4ghBackend) pathServicesList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	listPath := fmt.Sprintf("whitelist/%s/", project)
	entries, err := req.Storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// List all keys uploaded to a specific service
func (b *C4ghBackend) pathWhitelistedKeysList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	service := d.Get("service").(string)
	listPath := fmt.Sprintf("whitelist/%s/%s/", project, service)
	entries, err := req.Storage.List(ctx, listPath)

	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// Read a public key from Vault storage
func (b *C4ghBackend) pathWhitelistRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	service := d.Get("service").(string)
	name := d.Get("name").(string)
	entry, err := req.Storage.Get(ctx, "whitelist/"+project+"/"+service+"/"+name)
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
			"name":    result.Name,
		},
	}, nil
}

// check a whitelist exists by trying to read it
// this to decide if the operation is POST or PUT
// see https://github.com/hashicorp/vault/issues/22173#issuecomment-1762962763
func (b *C4ghBackend) pathWhitelistExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	resp, err := b.pathWhitelistRead(ctx, req, d)

	return resp != nil && !resp.IsError(), err
}

// Write a public key into Vault storage
func (b *C4ghBackend) pathWhitelistWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	pubkey := d.Get("pubkey").(string)
	flavor := d.Get("flavor").(string)
	service := d.Get("service").(string)
	name := d.Get("name").(string)

	if pubkey == "" {
		return logical.ErrorResponse("Missing public key"), nil
	}

	if service == "" {
		return logical.ErrorResponse("Service that owns the key needs to be specified."), nil
	}

	if project == "" {
		return logical.ErrorResponse("A project for the key needs to be specified."), nil
	}

	var formattedKey string

	switch strings.ToLower(flavor) {
	case "crypt4gh":
		formattedKey = pubkey
	case "ed25519":
		var edPublicKeyBytes [chacha20poly1305.KeySize]byte
		var c4ghPublicKey [chacha20poly1305.KeySize]byte
		edPubKey, err := base64.StdEncoding.DecodeString(pubkey)
		if err != nil {
			return nil, err
		}

		copy(edPublicKeyBytes[:], edPubKey)
		keys.PublicKeyToCurve25519(&c4ghPublicKey, edPubKey)
		formattedKey = base64.StdEncoding.EncodeToString(c4ghPublicKey[:])
	default:
		return logical.ErrorResponse("Key flavor not supported."), nil
	}

	keyPath := fmt.Sprintf("whitelist/%s/%s/%s", project, service, name)

	entry, err := logical.StorageEntryJSON(keyPath, map[string]interface{}{
		"key":     formattedKey,
		"flavor":  "crypt4gh",
		"project": project,
		"service": service,
		"name":    name,
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
func (b *C4ghBackend) pathWhitelistDelete(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	service := d.Get("service").(string)
	name := d.Get("name").(string)
	keyPath := fmt.Sprintf("whitelist/%s/%s/%s", project, service, name)

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
	pathServicesListHelpSynopsis           = `List of services into which keys have been uploaded`
	pathServicesListHelpDescription        = `Order of services not specified`
	pathWhitelistedKeysListHelpSynopsis    = `Lists the whitelisted keys for a specific service`
	pathWhitelistedKeysListHelpDescription = `Whitelisted key order is not specified`
)
