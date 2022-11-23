package c4ghtransit

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type FileData struct {
	Files map[string][]backupFileEntry `json:"archived_files"`
	Name  string                       `json:"name"`
	Key   string                       `json:"encryption_key"`
	Time  time.Time                    `json:"backup_time"`
}

type WhitelistData struct {
	Whitelisted []transitWhitelistEntrySansProject `json:"archived_whitelist"`
	Name        string                             `json:"name"`
	Time        time.Time                          `json:"backup_time"`
}

func (b *c4ghTransitBackend) pathRestore() *framework.Path {
	return &framework.Path{
		Pattern: "restore/" + framework.GenericNameRegex("type") + framework.OptionalParamRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"backup": {
				Type:        framework.TypeString,
				Description: "Backed up data to be restored. This should be the output from the 'backup/' endpoint.",
			},
			"name": {
				Type:        framework.TypeString,
				Description: "If set, this will be the name of the restored key/file.",
			},
			"type": {
				Type:        framework.TypeString,
				Description: "'keys', 'files', or 'whitelist' if user wishes to restore a key, a file or a whitelisted key",
			},
			"force": {
				Type:        framework.TypeBool,
				Description: "If set and a key/file by the given name exists, force the restore operation and override the key/file.",
				Default:     false,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathRestoreUpdate,
		},

		HelpSynopsis:    pathRestoreHelpSyn,
		HelpDescription: pathRestoreHelpDesc,
	}
}

func (b *c4ghTransitBackend) pathRestoreUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	backupB64 := d.Get("backup").(string)
	contentType := d.Get("type").(string)
	force := d.Get("force").(bool)
	if backupB64 == "" {
		return logical.ErrorResponse("'backup' must be supplied"), nil
	}

	// If a name is given, make sure it does not contain any slashes. The Transit
	// secret engine does not allow sub-paths in key names
	keyName := d.Get("name").(string)
	if strings.Contains(keyName, "/") {
		return nil, ErrInvalidKeyName
	}

	switch contentType {
	case "keys":
		return nil, b.lm.RestorePolicy(ctx, req.Storage, keyName, backupB64, force)
	case "files":
		return b.restoreFile(ctx, req.Storage, keyName, backupB64, force)
	case "whitelist":
		return b.restoreWhitelist(ctx, req.Storage, keyName, backupB64, force)
	default:
		return logical.ErrorResponse("Backup type not supported."), nil
	}
}

func (b *c4ghTransitBackend) restoreFile(ctx context.Context, storage logical.Storage, name, backup string, force bool) (*logical.Response, error) {
	backupBytes, err := base64.StdEncoding.DecodeString(backup)
	if err != nil {
		return nil, err
	}

	var fileData FileData
	err = jsonutil.DecodeJSON(backupBytes, &fileData)
	if err != nil {
		return nil, err
	}

	// Set a different name if desired
	if name != "" {
		fileData.Name = name
	}

	name = fileData.Name
	resp := &logical.Response{}

	if err = b.lm.RestorePolicy(ctx, storage, name, fileData.Key, force); err != nil {
		return nil, fmt.Errorf("Could not restore encryption key: %w", err)
	}

	for container, files := range fileData.Files {
		for _, file := range files {
			filePath := fmt.Sprintf("files/%s/%s/%s", name, container, file.Filename)
			entry, err := storage.Get(ctx, filePath)
			if err != nil {
				return nil, err
			}
			if entry != nil && !force {
				resp.AddWarning(fmt.Sprintf("file %s already exists", filePath))
				continue
			}

			newEntry, err := logical.StorageEntryJSON(filePath, map[string]interface{}{
				"header":     file.Entry.Header,
				"keyversion": file.Entry.Keyversion,
				"added":      file.Entry.Added,
			})

			if err != nil {
				return nil, err
			}
			if err := storage.Put(ctx, newEntry); err != nil {
				return nil, err
			}
		}
	}

	return resp, nil
}

func (b *c4ghTransitBackend) restoreWhitelist(ctx context.Context, storage logical.Storage, name, backup string, force bool) (*logical.Response, error) {
	backupBytes, err := base64.StdEncoding.DecodeString(backup)
	if err != nil {
		return nil, err
	}

	var whitelistData WhitelistData
	err = jsonutil.DecodeJSON(backupBytes, &whitelistData)
	if err != nil {
		return nil, err
	}

	// Set a different name if desired
	if name != "" {
		whitelistData.Name = name
	}

	name = whitelistData.Name
	resp := &logical.Response{}

	for _, data := range whitelistData.Whitelisted {
		listPath := fmt.Sprintf("whitelist/%s/%s", name, data.Service)
		entry, err := storage.Get(ctx, listPath)
		if err != nil {
			return nil, err
		}
		if entry != nil && !force {
			resp.AddWarning(fmt.Sprintf("project %s already has whitelisted key for service %s", name, data.Service))
			continue
		}

		newEntry, err := logical.StorageEntryJSON(listPath, map[string]interface{}{
			"key":     data.Key,
			"flavor":  data.Flavor,
			"service": data.Service,
			"project": name,
		})

		if err != nil {
			return nil, err
		}
		if err := storage.Put(ctx, newEntry); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

const (
	pathRestoreHelpSyn  = `Restore the named key, file, or whitelisted key`
	pathRestoreHelpDesc = `This path is used to restore the named key, file, or whitelisted key.`
)

var ErrInvalidKeyName = errors.New("Backup type names cannot be paths")
