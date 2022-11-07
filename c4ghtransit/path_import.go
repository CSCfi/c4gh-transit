package c4ghtransit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *c4ghTransitBackend) pathImport() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("name") + "/import",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the key",
			},
			"flavor": {
				Type:        framework.TypeString,
				Default:     "ed25519",
				Description: `The type of key being imported. "crypt4gh" and "ed25519" are supported. Defaults to "ed25519".`,
			},
			"kdfname": {
				Type:        framework.TypeString,
				Default:     "none",
				Description: `Name of the Key Derivation Function.`,
			},
			"password": {
				Type:        framework.TypeString,
				Default:     "",
				Description: `Password for the key`,
			},
			"ciphertext": {
				Type:        framework.TypeString,
				Description: `The base64-encoded ciphertext of the keys.`,
				Required:    true,
			},
			"allow_rotation": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "True if the imported key may be rotated within Vault; false otherwise.",
			},
			"auto_rotate_period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `The amount of time after which key will be rotated. 
Value of 0 (default) disables key rotation, otherwise the period 
of rotation needs to be at least one day, or 86400 seconds.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathImportWrite,
		},
		HelpSynopsis:    pathImportWriteSyn,
		HelpDescription: pathImportWriteDesc,
	}
}

func (b *c4ghTransitBackend) pathImportWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	flavor := d.Get("flavor").(string)
	cipherTextStr := d.Get("ciphertext").(string)
	autoRotatePeriod := time.Second * time.Duration(d.Get("auto_rotate_period").(int))
	allowrot := d.Get("allow_rotation").(bool)

	// Should we support password locked keys?
	// password := d.Get("password").(string)

	// kdfstr := d.Get("kdfname").(string)

	if autoRotatePeriod != 0 && autoRotatePeriod < (time.Hour*24) {
		return logical.ErrorResponse("Autorotate period needs to be disabled or at least a day. (86400 seconds)"), logical.ErrInvalidRequest
	}

	polReq := keysutil.PolicyRequest{
		Storage:                  req.Storage,
		Name:                     name,
		Derived:                  false,
		Exportable:               true,
		AllowPlaintextBackup:     true,
		AutoRotatePeriod:         autoRotatePeriod,
		AllowImportedKeyRotation: allowrot,
	}

	switch strings.ToLower(flavor) {
	case "ed25519":
		polReq.KeyType = keysutil.KeyType_ED25519
	case "crypt4gh":
		// Using ed25519 as internal key type for crypt4gh
		// converting between the two with an internal convenience function
		polReq.KeyType = keysutil.KeyType_ED25519
	default:
		return logical.ErrorResponse(fmt.Sprintf("unknown key type: %v", flavor)), logical.ErrInvalidRequest
	}

	p, _, err := b.GetPolicy(ctx, polReq, b.GetRandomReader())
	if err != nil {
		return nil, err
	}

	if p != nil {
		if b.System().CachingDisabled() {
			p.Unlock()
		}
		return nil, errors.New("the import path cannot be used with an existing key; use import-version to rotate an existing imported key")
	}

	key, err := base64.StdEncoding.DecodeString(cipherTextStr)
	if err != nil {
		return nil, err
	}

	switch strings.ToLower(flavor) {
	case "ed25519":
		err = b.lm.ImportPolicy(ctx, polReq, key, b.GetRandomReader())
		if err != nil {
			return nil, err
		}
	}

	return nil, nil
}

const (
	pathImportWriteSyn  = "Imports an externally-generated key into a new transit key"
	pathImportWriteDesc = "This path is used to import an externally-generated " +
		"key into Vault. The import operation creates a new key and cannot be used to " +
		"replace an existing key."
)

const pathImportVersionWriteSyn = "Imports an externally-generated key into an " +
	"existing imported key"

const pathImportVersionWriteDesc = "This path is used to import a new version of an " +
	"externally-generated key into an existing import key. The import_version endpoint " +
	"only supports importing key material into existing imported keys."
