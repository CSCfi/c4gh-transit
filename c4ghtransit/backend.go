package c4ghtransit

import (
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type c4ghTransitBackend struct {
	*framework.Backend
	lm                   *keysutil.LockManager
	configMutex          sync.RWMutex
	cacheSizeChanged     bool
	checkAutoRotateAfter time.Time
	autoRotateOnce       sync.Once
}

const minCacheSize = 10

var _ logical.Factory = Factory

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend(ctx, conf)
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend(ctx context.Context, conf *logical.BackendConfig) (*c4ghTransitBackend, error) {
	var b c4ghTransitBackend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"files/",
				"whitelist/",
				"archive/",
				"policy/",
			},
			Unauthenticated: []string{
				"public_key/",
			},
		},
		Paths: []*framework.Path{
			b.pathRotate(),
			b.pathKeys(),
			b.pathKeysList(),
			b.pathWhitelist(),
			b.pathListServices(),
			b.pathListWhitelistedKeys(),
			b.pathFiles(),
			b.pathListFiles(),
			b.pathListContainers(),
			b.pathImport(),
			b.pathBackup(),
			b.pathBackupList(),
			b.pathRestore(),
			b.pathRewrap(),
		},

		Secrets:      []*framework.Secret{},
		Invalidate:   b.invalidate,
		BackendType:  logical.TypeLogical,
		PeriodicFunc: b.periodicFunc,
	}

	// Code sourced from Vault repository under MPL-2.0
	// determine cacheSize to use. Defaults to 0 which means unlimited
	cacheSize := 0
	useCache := true
	// useCache := !conf.System.CachingDisabled()
	// if useCache {
	// 	var err error
	// 	cacheSize, err = GetCacheSizeFromStorage(ctx, conf.StorageView)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("Error retrieving cache size from storage: %w", err)
	// 	}

	// 	if cacheSize != 0 && cacheSize < minCacheSize {
	// 		b.Logger().Warn("size %d is less than minimum %d. Cache size is set to %d", cacheSize, minCacheSize, minCacheSize)
	// 		cacheSize = minCacheSize
	// 	}
	// }

	var err error
	b.lm, err = keysutil.NewLockManager(useCache, cacheSize)
	if err != nil {
		return nil, err
	}
	// End MPL-2.0

	return &b, nil
}

// Code sourced from Vault repository under MPL-2.0
func GetCacheSizeFromStorage(ctx context.Context, s logical.Storage) (int, error) {
	size := 0
	entry, err := s.Get(ctx, "config/cache")
	if err != nil {
		return 0, err
	}
	if entry != nil {
		var storedCache configCache
		if err := entry.DecodeJSON(&storedCache); err != nil {
			return 0, err
		}
		size = storedCache.Size
	}
	return size, nil
}

func (b *c4ghTransitBackend) GetPolicy(ctx context.Context, polReq keysutil.PolicyRequest, rand io.Reader) (retP *keysutil.Policy, retUpserted bool, retErr error) {
	b.configMutex.RLock()
	//nolint:nestif
	if b.lm.GetUseCache() && b.cacheSizeChanged {
		var err error
		currentCacheSize := b.lm.GetCacheSize()
		storedCacheSize, err := GetCacheSizeFromStorage(ctx, polReq.Storage)
		if err != nil {
			b.configMutex.RUnlock()
			return nil, false, err
		}
		if currentCacheSize != storedCacheSize {
			err = b.lm.InitCache(storedCacheSize)
			if err != nil {
				b.configMutex.RUnlock()
				return nil, false, err
			}
		}
		// Release the read lock and acquire the write lock
		b.configMutex.RUnlock()
		b.configMutex.Lock()
		defer b.configMutex.Unlock()
		b.cacheSizeChanged = false
	} else {
		b.configMutex.RUnlock()
	}
	p, _, err := b.lm.GetPolicy(ctx, polReq, rand)
	if err != nil {
		return p, false, err
	}
	return p, true, nil
}

func (b *c4ghTransitBackend) invalidate(ctx context.Context, key string) {
	if b.Logger().IsDebug() {
		b.Logger().Debug("invalidating key", "key", key)
	}
	switch {
	case strings.HasPrefix(key, "policy/"):
		name := strings.TrimPrefix(key, "policy/")
		b.lm.InvalidatePolicy(name)
	case strings.HasPrefix(key, "cache-config/"):
		// Acquire the lock to set the flag to indicate that cache size needs to be refreshed from storage
		b.configMutex.Lock()
		defer b.configMutex.Unlock()
		b.cacheSizeChanged = true
	}
}

// periodicFunc is a central collection of functions that run on an interval.
// Anything that should be called regularly can be placed within this method.
func (b *c4ghTransitBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	// These operations ensure the auto-rotate only happens once simultaneously. It's an unlikely edge
	// given the time scale, but a safeguard nonetheless.
	var err error
	didAutoRotate := false
	autoRotateOnceFn := func() {
		err = b.autoRotateKeys(ctx, req)
		didAutoRotate = true
	}
	b.autoRotateOnce.Do(autoRotateOnceFn)
	if didAutoRotate {
		b.autoRotateOnce = sync.Once{}
	}

	return err
}

// autoRotateKeys retrieves all transit keys and rotates those which have an
// auto rotate period defined which has passed. This operation only happens
// on primary nodes and performance secondary nodes which have a local mount.
func (b *c4ghTransitBackend) autoRotateKeys(ctx context.Context, req *logical.Request) error {
	// Only check for autorotation once a day to avoid unnecessarily iterating
	// over all keys too frequently.
	if time.Now().Before(b.checkAutoRotateAfter) {
		return nil
	}
	b.checkAutoRotateAfter = time.Now().Add(24 * time.Hour)

	// Early exit if not a primary or performance secondary with a local mount.
	if b.System().ReplicationState().HasState(consts.ReplicationDRSecondary|consts.ReplicationPerformanceStandby) ||
		(!b.System().LocalMount() && b.System().ReplicationState().HasState(consts.ReplicationPerformanceSecondary)) {
		return nil
	}

	// Retrieve all keys and loop over them to check if they need to be rotated.
	keys, err := req.Storage.List(ctx, "policy/")
	if err != nil {
		return err
	}

	// Collect errors in a multierror to ensure a single failure doesn't prevent
	// all keys from being rotated.
	var errs *multierror.Error

	for _, key := range keys {
		p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
			Storage: req.Storage,
			Name:    key,
		}, b.GetRandomReader())
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		// If the policy is nil, move onto the next one.
		if p == nil {
			continue
		}

		err = b.rotateIfRequired(ctx, req, key, p)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	return errs.ErrorOrNil()
}

// rotateIfRequired rotates a key if it is due for autorotation.
func (b *c4ghTransitBackend) rotateIfRequired(ctx context.Context, req *logical.Request, key string, p *keysutil.Policy) error {
	if !b.System().CachingDisabled() {
		p.Lock(true)
	}
	defer p.Unlock()

	// If the key is imported, it can only be rotated from within Vault if allowed.
	if p.Imported && !p.AllowImportedKeyRotation {
		return nil
	}

	// If the policy's automatic rotation period is 0, it should not
	// automatically rotate.
	if p.AutoRotatePeriod == 0 {
		return nil
	}

	// Retrieve the latest version of the policy and determine if it is time to rotate.
	latestKey := p.Keys[strconv.Itoa(p.LatestVersion)]
	if time.Now().After(latestKey.CreationTime.Add(p.AutoRotatePeriod)) {
		if b.Logger().IsDebug() {
			b.Logger().Debug("automatically rotating key", "key", key)
		}
		return p.Rotate(ctx, req.Storage, b.GetRandomReader())

	}
	return nil
}

// End MPL-2.0
const backendHelp = `
c4hg-transit implements an implementation of vault transit API using crypt4gh
encryption file specification. The API can re-encrypt headers on the fly to
allow accessing file contents with a different public key without
re-encrypting the whole file. Keys used for header encryption can be added in
the /keys endpoint, public keys for transit can be added in /whitelist
endpoint.
`
