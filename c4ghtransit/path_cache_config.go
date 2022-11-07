package c4ghtransit

import (
	"context"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *c4ghTransitBackend) pathCacheConfig() *framework.Path {
	return &framework.Path{
		Pattern: "cache-config",
		Fields: map[string]*framework.FieldSchema{
			"size": {
				Type:        framework.TypeInt,
				Required:    false,
				Default:     0,
				Description: `Size of cache, use 0 for an unlimited cache size, defaults to 0`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCacheConfigRead,
				Summary:  "Returns the size of the active cache",
			},

			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCacheConfigWrite,
				Summary:  "Configures a new cache of the specified size",
			},

			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathCacheConfigWrite,
				Summary:  "Configures a new cache of the specified size",
			},
		},

		HelpSynopsis:    pathCacheConfigHelpSyn,
		HelpDescription: pathCacheConfigHelpDesc,
	}
}

func (b *c4ghTransitBackend) pathCacheConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// get target size
	cacheSize := d.Get("size").(int)
	if cacheSize != 0 && cacheSize < minCacheSize {
		return logical.ErrorResponse("size must be 0 or a value greater or equal to %d", minCacheSize), logical.ErrInvalidRequest
	}

	// store cache size
	entry, err := logical.StorageEntryJSON("config/cache", &configCache{
		Size: cacheSize,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	err = b.lm.InitCache(cacheSize)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

type configCache struct {
	Size int `json:"size"`
}

func (b *c4ghTransitBackend) pathCacheConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// error if no cache is configured
	if !b.lm.GetUseCache() {
		return nil, errors.New(
			"caching is disabled for this transit mount",
		)
	}

	// Compare current and stored cache sizes. If they are different warn the user.
	currentCacheSize := b.lm.GetCacheSize()
	storedCacheSize, err := GetCacheSizeFromStorage(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if currentCacheSize != storedCacheSize {
		err = b.lm.InitCache(storedCacheSize)
		if err != nil {
			return nil, err
		}
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"size": storedCacheSize,
		},
	}

	return resp, nil
}

const pathCacheConfigHelpSyn = `Configure caching strategy`

const pathCacheConfigHelpDesc = `
This path is used to configure and query the cache size of the active cache, a size of 0 means unlimited.
`
