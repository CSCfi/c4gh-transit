package c4ghtransit

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

type backupFileEntry struct {
	Filename string       `json:"filename"`
	Entry    fileEntryMap `json:"entry"`
}

type transitWhitelistEntrySansProject struct {
	Key     string `json:"key"`
	Flavor  string `json:"flavor"`
	Service string `json:"service"`
	Name    string `json:"name"`
}

func (b *c4ghTransitBackend) pathBackup() *framework.Path {
	return &framework.Path{
		Pattern: "backup/" + framework.GenericNameRegex("type") + "/" + framework.GenericNameRegex("project"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeString,
				Description: "The project the key or file belongs to",
			},
			"type": {
				Type:        framework.TypeString,
				Description: "'keys', 'files', or 'whitelist' if user wishes to backup a key, a file or a whitelisted key",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathBackupRead,
		},

		HelpSynopsis:    pathBackupHelpSyn,
		HelpDescription: pathBackupHelpDescription,
	}
}

func (b *c4ghTransitBackend) pathBackupRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	contentType := d.Get("type").(string)
	project := d.Get("project").(string)

	var backup string
	var err error
	switch contentType {
	case "keys":
		backup, err = b.lm.BackupPolicy(ctx, req.Storage, project)
	case "files":
		backup, err = b.backupFile(ctx, req.Storage, project)
	case "whitelist":
		backup, err = b.backupWhitelist(ctx, req.Storage, project)
	default:
		return logical.ErrorResponse("Backup type not supported."), nil
	}

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"backup": backup,
		},
	}, nil
}

func (b *c4ghTransitBackend) backupFile(ctx context.Context, storage logical.Storage, project string) (string, error) {
	listPath := fmt.Sprintf("files/%s/", project)
	containers, err := storage.List(ctx, listPath)
	if err != nil {
		return "", err
	}
	if containers == nil {
		return "", fmt.Errorf(fmt.Sprintf("Project %q not found", project))
	}

	backup := map[string]interface{}{"backup_time": time.Now(), "name": project}
	fileData := make(map[string][]backupFileEntry, len(containers))

	for _, c := range containers {
		container := strings.TrimSuffix(c, "/")
		listPath = fmt.Sprintf("files/%s/%s/", project, container)
		files, err := storage.List(ctx, listPath)
		if err != nil {
			return "", err
		}
		if files == nil {
			continue
		}

		entries := make([]backupFileEntry, 0, len(files))
		for _, file := range files {
			filePath := fmt.Sprintf("files/%s/%s/%s", project, container, file)
			entry, err := storage.Get(ctx, filePath)
			if err != nil {
				return "", err
			}
			if entry != nil {
				var result fileEntryMap
				if err := entry.DecodeJSON(&result); err != nil {
					return "", err
				}

				entries = append(entries, backupFileEntry{file, result})
			}
		}

		fileData[container] = entries
	}

	keyBackup, err := b.lm.BackupPolicy(ctx, storage, project)
	if err != nil {
		return "", err
	}

	backup["archived_files"] = fileData
	backup["encryption_key"] = keyBackup

	encodedBackup, err := jsonutil.EncodeJSON(backup)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encodedBackup), nil
}

func (b *c4ghTransitBackend) backupWhitelist(ctx context.Context, storage logical.Storage, project string) (string, error) {
	listPath := fmt.Sprintf("whitelist/%s/", project)
	services, err := storage.List(ctx, listPath)
	if err != nil {
		return "", err
	}
	if services == nil {
		return "", fmt.Errorf(fmt.Sprintf("No whitelisted keys found for %q", project))
	}

	backup := map[string]interface{}{"backup_time": time.Now(), "name": project}
	entries := make([]transitWhitelistEntrySansProject, 0, len(services))
	for _, s := range services {
		service := strings.TrimSuffix(s, "/")
		keyNames, err := storage.List(ctx, "whitelist/"+project+"/"+service+"/")
		if err != nil {
			return "", err
		}
		if keyNames == nil {
			continue
		}

		for _, keyName := range keyNames {
			entry, err := storage.Get(ctx, "whitelist/"+project+"/"+service+"/"+keyName)
			if err != nil {
				return "", err
			}
			if entry != nil {
				var result transitWhitelistEntrySansProject
				if err := entry.DecodeJSON(&result); err != nil {
					return "", err
				}
				entries = append(entries, result)
			}
		}
	}

	backup["archived_whitelist"] = entries
	encodedBackup, err := jsonutil.EncodeJSON(backup)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encodedBackup), nil
}

const (
	pathBackupHelpSyn         = `Backup the named key, header, or whitelisted keys`
	pathBackupHelpDescription = `This path is used for backups.`
)
