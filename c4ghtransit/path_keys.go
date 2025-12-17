package c4ghtransit

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/structs"
	"github.com/neicnordic/crypt4gh/keys"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathKeys extends the Vault API with a "/keys"
// endpoint.
func (b *C4ghBackend) pathKeys() *framework.Path {
	return &framework.Path{
		Pattern: "keys/" + framework.GenericNameRegex("project"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "The project a key belongs to",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Project",
					Value: "project_2001111",
				},
			},
			"flavor": {
				Type:        framework.TypeString,
				Default:     "ed25519",
				Description: "Key type, ed25519 or crypt4gh",
				Required:    true,
				Query:       true,
			},
			"auto_rotate_period": {
				Type:    framework.TypeDurationSecond,
				Default: 0,
				Description: `The amount of time after which key will be rotated.
Value of 0 (default) disables key rotation, otherwise the period
of rotation needs to be at least one day, or 86400 seconds.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeyUpdate,
				Summary:  "Create a key-pair for the project",
				Description: "The request creates a new key for a project. " +
					"If a key already exists, nothing happens. The request body should be empty.",
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {
						{
							Description: http.StatusText(http.StatusNoContent),
						},
					},
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.pathKeyRead,
				Summary:     "Retrieve the project's public key",
				Description: "If a key doesn't yet exist, it is created and returned.",
				Responses: map[int][]framework.Response{
					http.StatusOK: {
						{
							Description: http.StatusText(http.StatusOK),
							Example: &logical.Response{
								Data: map[string]any{
									"allow_plaintext_backup": true,
									"auto_rotate_period":     0,
									"deletion_allowed":       false,
									"exportable":             true,
									"imported_key":           false,
									"keys": map[string]any{
										"1": map[string]any{
											"creation_time":      "2022-12-05T10:54:26.405686018+02:00",
											"project":            "ed25519",
											"public_key_64":      "NAGGNoD65560KBO7QxiVFnjanwalx1SD/QJu3hD/LTU=",
											"public_key_c4gh":    "-----BEGIN CRYPT4GH PUBLIC KEY-----\nKuFzMZ35PW98MwRcspIow3G1Nrvz8gnEK9c+yQgSMXc=\n-----END CRYPT4GH PUBLIC KEY-----\n",
											"public_key_c4gh_64": "KuFzMZ35PW98MwRcspIow3G1Nrvz8gnEK9c+yQgSMXc=",
										},
									},
									"latest_version":         1,
									"min_available_version":  0,
									"min_decryption_version": 1,
									"min_encryption_version": 0,
									"name":                   "project",
									"supports_decryption":    false,
									"supports_derivation":    true,
									"supports_encryption":    false,
									"supports_signing":       true,
									"type":                   "ed25519",
								},
							},
						},
					},
				},
			},
		},
		HelpSynopsis:    pathKeyHelpSynopsis,
		HelpDescription: pathKeyHelpDescription,
	}
}

func (b *C4ghBackend) pathKeysList() *framework.Path {
	return &framework.Path{
		Pattern: "keys/?$",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListKeys,
				Summary:  "List available keys",
			},
		},
		HelpSynopsis:    pathKeysListHelpSynopsis,
		HelpDescription: pathKeysListHelpDescription,
	}
}

// pathKeyUpdate creates a new key
func (b *C4ghBackend) pathKeyUpdate(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	flavor := d.Get("flavor").(string)
	autorotate := time.Second * time.Duration(d.Get("auto_rotate_period").(int))

	if autorotate != 0 && autorotate < (time.Hour*24) {
		return logical.ErrorResponse("Autorotate period needs to be disabled or at least a day. (86400 seconds)"), logical.ErrInvalidRequest
	}

	polReq := keysutil.PolicyRequest{
		Upsert:               true,
		Storage:              req.Storage,
		Name:                 project,
		Derived:              false,
		Convergent:           false,
		Exportable:           true,
		AllowPlaintextBackup: true,
		AutoRotatePeriod:     0,
	}

	switch flavor {
	case "ed25519":
		polReq.KeyType = keysutil.KeyType_ED25519
	case "crypt4gh":
		// crypt4gh keys are directly calculable from internal representation and returned by default.
		polReq.KeyType = keysutil.KeyType_ED25519
	default:
		return logical.ErrorResponse(fmt.Sprintf("unknown key type %v", flavor)), logical.ErrInvalidRequest
	}
	polReq.KeyType = keysutil.KeyType_ED25519

	p, upserted, err := b.GetPolicy(ctx, polReq, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("error generating key: returned policy was nil")
	}
	if b.System().CachingDisabled() {
		p.Unlock()
	}

	resp := &logical.Response{}
	if !upserted {
		resp.AddWarning(fmt.Sprintf("key %s already existed", project))

		return resp, nil
	}

	return nil, nil
}

type pubKeyRet struct {
	Project         string    `json:"project" structs:"project" mapstructure:"project"`
	PublicKey64     string    `json:"public_key_base_64" structs:"public_key_64" mapstructure:"public_key_64"`
	PublicKeyC4gh   string    `json:"public_key_c4gh" structs:"public_key_c4gh" mapstructure:"public_key_c4gh"`
	PublicKeyC4gh64 string    `json:"public_key_c4gh_64" structs:"public_key_c4gh_64" mapstructure:"public_key_c4gh_64"`
	CreationTime    time.Time `json:"creation_time" structs:"creation_time" mapstructure:"creation_time"`
}

// pathKeyRead displays key metadata, e.g. expiration, public key entry
func (b *C4ghBackend) pathKeyRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    project,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil { // key does not exist
		resp, err := b.pathKeyUpdate(ctx, req, d)
		if err != nil {
			return resp, err
		}

		return b.pathKeyRead(ctx, req, d)
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	resp := &logical.Response{
		Data: map[string]any{
			"name":                   p.Name,
			"type":                   p.Type.String(),
			"deletion_allowed":       p.DeletionAllowed,
			"min_available_version":  p.MinAvailableVersion,
			"min_decryption_version": p.MinDecryptionVersion,
			"min_encryption_version": p.MinEncryptionVersion,
			"latest_version":         p.LatestVersion,
			"exportable":             p.Exportable,
			"allow_plaintext_backup": p.AllowPlaintextBackup,
			"supports_encryption":    p.Type.EncryptionSupported(),
			"supports_decryption":    p.Type.DecryptionSupported(),
			"supports_signing":       p.Type.SigningSupported(),
			"supports_derivation":    p.Type.DerivationSupported(),
			"auto_rotate_period":     int64(p.AutoRotatePeriod.Seconds()),
			"imported_key":           p.Imported,
		},
	}

	if p.KeySize != 0 {
		resp.Data["key_size"] = p.KeySize
	}

	if p.Imported {
		resp.Data["imported_key_allow_rotation"] = p.AllowImportedKeyRotation
	}

	if p.BackupInfo != nil {
		resp.Data["backup_info"] = map[string]any{
			"time":    p.BackupInfo.Time,
			"version": p.BackupInfo.Version,
		}
	}
	if p.RestoreInfo != nil {
		resp.Data["restore_info"] = map[string]any{
			"time":    p.RestoreInfo.Time,
			"version": p.RestoreInfo.Version,
		}
	}

	retKeys := map[string]map[string]any{}
	for k, v := range p.Keys {
		var c4ghPublicKey [chacha20poly1305.KeySize]byte
		publicKey, err := base64.StdEncoding.DecodeString(v.FormattedPublicKey)
		if err != nil {
			return nil, err
		}

		keys.PublicKeyToCurve25519(&c4ghPublicKey, publicKey)
		c4ghFormattedPublicKey := base64.StdEncoding.EncodeToString(c4ghPublicKey[:])

		key := pubKeyRet{
			Project:         project,
			PublicKey64:     v.FormattedPublicKey,
			PublicKeyC4gh:   fmt.Sprintf("-----BEGIN CRYPT4GH PUBLIC KEY-----\n%s\n-----END CRYPT4GH PUBLIC KEY-----\n", c4ghFormattedPublicKey),
			PublicKeyC4gh64: c4ghFormattedPublicKey,
			CreationTime:    v.CreationTime,
		}
		if key.CreationTime.IsZero() {
			key.CreationTime = time.Unix(v.DeprecatedCreationTime, 0)
		}
		retKeys[k] = structs.New(key).Map()
	}
	resp.Data["keys"] = retKeys

	return resp, nil
}

// pathListKeys lists available keys
func (b *C4ghBackend) pathListKeys(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData,
) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "policy/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const (
	pathKeyHelpSynopsis    = `Manages the encryption keys used for decrypting headers`
	pathKeyHelpDescription = `
This path allows you to add keys for decrypting the headers when performing
re-encryption on stored headers. A full key history will always be preserved,
i.e. key deletion and updates are forbidden.
`
	pathKeysListHelpSynopsis    = `List the managed encryption keys used for decryption.`
	pathKeysListHelpDescription = `
This path allows you to list all keys that have been added for decrypting the
stored headers on re-encryption. A full key history will be listed when a call
to list key is given.
	`
)
