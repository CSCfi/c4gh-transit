package c4ghtransit

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
)

func (b *C4ghBackend) pathRewrap() *framework.Path {
	return &framework.Path{
		Pattern: "rewrap/" + framework.GenericNameRegex("project"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "The project a key belongs to",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathRewrapWrite,
			},
		},

		HelpSynopsis:    pathRewrapHelpSyn,
		HelpDescription: pathRewrapHelpDesc,
	}
}

func (b *C4ghBackend) pathRewrapWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	project := d.Get("project").(string)
	listPath := fmt.Sprintf("files/%s/", project)
	containers, err := req.Storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}
	if containers == nil {
		return nil, fmt.Errorf("project %q not found", project)
	}

	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    project,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	latestKey, ok := p.Keys[strconv.Itoa(p.LatestVersion)]
	if !ok {
		return logical.ErrorResponse("Latest key version not found."), nil
	}

	publicKey, err := base64.StdEncoding.DecodeString(latestKey.FormattedPublicKey)
	if err != nil {
		return nil, err
	}

	var c4ghPublicKey [chacha20poly1305.KeySize]byte
	keys.PublicKeyToCurve25519(&c4ghPublicKey, publicKey)

	for _, c := range containers {
		container := strings.TrimSuffix(c, "/")
		listPath = fmt.Sprintf("files/%s/%s/", project, container)
		files, err := req.Storage.List(ctx, listPath)
		if err != nil {
			return nil, err
		}
		if files == nil {
			continue
		}

		for _, file := range files {
			filePath := fmt.Sprintf("files/%s/%s/%s", project, container, file)
			entry, err := req.Storage.Get(ctx, filePath)
			if err != nil {
				return nil, err
			}
			if entry == nil {
				continue
			}

			var result fileEntryMap
			if err := entry.DecodeJSON(&result); err != nil {
				return nil, err
			}

			for k, v := range result.Headers {
				if v.Keyversion == p.LatestVersion {
					continue
				}

				headerBytes, err := base64.StdEncoding.DecodeString(v.Header)
				if err != nil {
					return nil, err
				}

				key, err := p.GetKey(nil, v.Keyversion, p.KeySize)
				if err != nil {
					return nil, err
				}
				if key == nil {
					return logical.ErrorResponse("Key version %s not found.", v.Keyversion), nil
				}

				// Copy the key to a fixed length array since NewHeader is picky
				var privkey [chacha20poly1305.KeySize]byte
				keys.PrivateKeyToCurve25519(&privkey, key)

				newBinaryHeader, err := headers.ReEncryptHeader(headerBytes, privkey, [][chacha20poly1305.KeySize]byte{c4ghPublicKey})
				if err != nil {
					return nil, err
				}

				// Update header after it was successfully decrypted
				result.Headers[k] = reencryptFileEntry{
					Header:     base64.StdEncoding.EncodeToString(newBinaryHeader),
					Keyversion: p.LatestVersion,
					Added:      time.Now(),
				}
			}

			// Add rewrapped headers to the database
			newEntry, err := logical.StorageEntryJSON(filePath, result)
			if err != nil {
				return nil, err
			}

			if err := req.Storage.Put(ctx, newEntry); err != nil {
				return nil, err
			}
		}
	}

	return nil, nil
}

const pathRewrapHelpSyn = `Rewrap headers`

const pathRewrapHelpDesc = `
After key rotation, this function can be used to rewrap the headers
with the latest version of the named key.`
