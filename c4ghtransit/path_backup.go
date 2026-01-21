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
	"golang.org/x/sync/errgroup"
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

func (b *C4ghBackend) pathBackup() *framework.Path {
	return &framework.Path{
		Pattern: "backup/" + framework.GenericNameRegex("type") + "/" + framework.GenericNameRegex("project"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeString,
				Description: "The project the key or file belongs to",
				Required:    true,
			},
			"type": {
				Type:        framework.TypeString,
				Description: "'keys', 'files', or 'whitelist' if user wishes to backup a key, a file or a whitelisted key",
				Required:    true,
			},
			"limit": {
				Type:        framework.TypeInt,
				Description: "The maximum size of one backup chunk. Only applicable for files",
				Required:    true,
			},
			"force": {
				Type:        framework.TypeBool,
				Description: "Force limit by splitting container data into separate chunks when necessary. Only applicable for files",
				Default:     false,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathBackupRead,
			},
		},

		HelpSynopsis:    pathBackupHelpSyn,
		HelpDescription: pathBackupHelpDescription,
	}
}

func (b *C4ghBackend) pathBackupList() *framework.Path {
	return &framework.Path{
		Pattern: "backup/" + framework.GenericNameRegex("type") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"type": {
				Type:        framework.TypeString,
				Description: "'keys' or 'files' if user wishes to list projects with keys or files stored.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathListBackups,
			},
		},
		HelpSynopsis:    pathBackupListHelpSynopsis,
		HelpDescription: pathBackupListHelpDescription,
	}
}

func (b *C4ghBackend) pathListBackups(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	contentType := d.Get("type").(string)

	switch contentType {
	case "files":
		listPath := "files/"

		entries, err := req.Storage.List(ctx, listPath)

		if err != nil {
			return nil, err
		}

		return logical.ListResponse(entries), nil
	case "keys":
		entries, err := req.Storage.List(ctx, "policy/")
		if err != nil {
			return nil, err
		}

		return logical.ListResponse(entries), nil
	default:
		return logical.ErrorResponse("Backup listing type not supported."), nil
	}
}

func (b *C4ghBackend) pathBackupRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	contentType := d.Get("type").(string)
	project := d.Get("project").(string)

	var backup any
	var err error
	switch contentType {
	case "keys":
		backup, err = b.lm.BackupPolicy(ctx, req.Storage, project)
	case "files":
		limit := d.Get("limit").(int)
		force := d.Get("force").(bool)
		backup, err = b.backupFiles(ctx, req.Storage, project, limit, force)
	case "whitelist":
		backup, err = b.backupWhitelist(ctx, req.Storage, project)
	default:
		return logical.ErrorResponse("Backup type not supported"), nil
	}

	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]any{
			"backup": backup,
		},
	}, nil
}

func (b *C4ghBackend) backupFiles(ctx context.Context, storage logical.Storage, project string, sizeLimit int, forceSplit bool) ([]string, error) {
	listPath := fmt.Sprintf("files/%s/", project)
	containers, err := storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}
	if containers == nil {
		return nil, fmt.Errorf("project %q not found", project)
	}

	keyBackup, err := b.lm.BackupPolicy(ctx, storage, project)
	if err != nil {
		return nil, err
	}

	batches := []string{}
	backupBase := `{"backup_time": "` + time.Now().Format(time.RFC3339Nano) + `","name": "` + project + `","encryption_key": "` + keyBackup + `","archived_files": {%s}}`
	minBatchSize := len(fmt.Sprintf(backupBase, ""))

	g, ctxGroup := errgroup.WithContext(ctx)

	// Results are sent to the following goroutine via this channel
	respc := make(chan string)
	wait := make(chan error)

	go func() {
		fileData := ""

		addToBatches := func() {
			backupStr := fmt.Sprintf(backupBase, fileData)
			batches = append(batches, base64.StdEncoding.EncodeToString([]byte(backupStr)))

			fileData = ""
		}

		for next := range respc {
			switch {
			case len(fileData) == 0:
				fileData = next
			case 4*((minBatchSize+len(fileData)+len(next)+1+2)/3) > sizeLimit:
				addToBatches()
				fileData = next
			default:
				fileData += "," + next
			}
		}

		addToBatches()
		wait <- nil
	}()

	for _, c := range containers {
		g.Go(func() error {
			container := strings.TrimSuffix(c, "/")
			listPath = fmt.Sprintf("files/%s/%s/", project, container)
			files, err := storage.List(ctx, listPath)
			if err != nil {
				return err
			}
			if files == nil {
				return nil
			}

			entries := make([]backupFileEntry, 0, len(files))
			for _, file := range files {
				filePath := fmt.Sprintf("files/%s/%s/%s", project, container, file)
				entry, err := storage.Get(ctx, filePath)
				if err != nil {
					return err
				}
				if entry != nil {
					var result fileEntryMap
					if err := entry.DecodeJSON(&result); err != nil {
						return err
					}

					entries = append(entries, backupFileEntry{file, result})
				}
			}

			return b.sendContainer(ctxGroup, container, entries, respc, sizeLimit-minBatchSize, forceSplit)
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	close(respc)
	<-wait

	return batches, nil
}

func (b *C4ghBackend) sendContainer(
	ctx context.Context,
	container string,
	files []backupFileEntry,
	ch chan<- string,
	maxLen int,
	splitContainer bool,
) error {
	encodedFiles, err := jsonutil.EncodeJSON(files)
	if err != nil {
		return err
	}

	size := 4 * ((len(encodedFiles) + len(container) + 3 + 2) / 3) // Calculate size for base64 data (no trailing comma)
	if size > maxLen {
		if !splitContainer {
			return fmt.Errorf("container %s is too large (~%d bytes)", container, size)
		}
		if len(files) == 1 {
			return fmt.Errorf("file %s in container %s is too large (~%d bytes)", files[0].Filename, container, size)
		}

		err = b.sendContainer(ctx, container, files[:len(files)/2], ch, maxLen, splitContainer)
		if err != nil {
			return err
		}

		return b.sendContainer(ctx, container, files[len(files)/2:], ch, maxLen, splitContainer)
	}

	select {
	case ch <- fmt.Sprintf("\"%s\":%s", container, string(encodedFiles)):
	case <-ctx.Done():
		return context.Cause(ctx)
	}

	return nil
}

func (b *C4ghBackend) backupWhitelist(ctx context.Context, storage logical.Storage, project string) (string, error) {
	listPath := fmt.Sprintf("whitelist/%s/", project)
	services, err := storage.List(ctx, listPath)
	if err != nil {
		return "", err
	}
	if services == nil {
		return "", fmt.Errorf("no whitelisted keys found for %q", project)
	}

	backup := WhitelistData{Time: time.Now(), Name: project}
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

	backup.Whitelisted = entries
	encodedBackup, err := jsonutil.EncodeJSON(backup)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encodedBackup), nil
}

const (
	pathBackupHelpSyn             = `Backup the named key, header, or whitelisted keys`
	pathBackupHelpDescription     = `This path is used for backups.`
	pathBackupListHelpSynopsis    = `Lists possible keys or projects into which headers have been uploaded`
	pathBackupListHelpDescription = `Listing order is not specified`
)
