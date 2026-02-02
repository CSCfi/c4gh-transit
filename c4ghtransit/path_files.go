package c4ghtransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sync/errgroup"
)

type reencryptFileEntry struct {
	Header     string    `json:"header" structs:"header" mapstructure:"header"`
	Keyversion int       `json:"keyversion" structs:"keyversion" mapstructure:"keyversion"`
	Added      time.Time `json:"added" struct:"added" mapstructure:"added"`
}

type fileEntryMap struct {
	Headers       map[string]reencryptFileEntry `json:"headers" structs:"headers" mapstructure:"headers"`
	LatestVersion int                           `json:"latest_version" structs:"latest_version" mapstructure:"latest_version"`
}

type batchResult struct {
	container string
	responses map[string]any
	missing   iter.Seq[string]
}

// pathFiles provides c4ghtransit/files endpoint for storing headers encrypted with keys stored in vault
func (b *C4ghBackend) pathFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/" + framework.MatchAllRegex("file"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Project",
					Value: "project_2001111",
				},
			},
			"container": {
				Type:        framework.TypeString,
				Description: "Container or bucket that the file belongs to",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Container",
					Value: "container_name",
				},
			},
			"file": {
				Type:        framework.TypeString,
				Description: "Full object path of the file the uploaded header belongs to",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "File",
					Value: "path/to/object",
				},
			},
			"header": {
				Type:        framework.TypeString,
				Description: "Base64 encoded string of an encrypted header encrypted with a key known to the c4gh-transit plugin. Must be in the request body for update operations.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:  "Header",
					Value: "b64encoded",
				},
			},
			"service": {
				Type:        framework.TypeNameString,
				Description: "Service that requests the file, matches the whitelist service name. ",
				Required:    true,
				Query:       true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Service",
				},
			},
			"key": {
				Type:        framework.TypeNameString,
				Description: "Name of whitelisted key the service wants to use.",
				Required:    true,
				Query:       true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Key",
				},
			},
			"owner": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container (if the container is shared).",
				Default:     "",
				Required:    false,
				Query:       true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Owner",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:    b.pathFilesRead,
				Summary:     "Download a re-encrypted header",
				Description: "The header is re-encrypted with the specified **service** and **key** combination.",
				Responses: map[int][]framework.Response{
					http.StatusOK: {
						{
							Description: http.StatusText(http.StatusOK),
						},
					},
				},
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback:    b.pathFilesWrite,
				Summary:     "Upload an encrypted header",
				Description: pathFilesUpdateOperationDescription,
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {
						{
							Description: http.StatusText(http.StatusNoContent),
						},
					},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathFilesUpdate,
				Summary:     "Upload an encrypted header",
				Description: pathFilesUpdateOperationDescription,
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {
						{
							Description: http.StatusText(http.StatusNoContent),
						},
					},
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathFilesDelete,
				Summary:  "Delete an encrypted header",
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {
						{
							Description: http.StatusText(http.StatusNoContent),
						},
					},
				},
			},
		},
		ExistenceCheck:  b.pathFilesExistenceCheck,
		HelpSynopsis:    pathFilesHelpSynopsis,
		HelpDescription: pathFilesHelpDescription,
	}
}

// pathContainers list containers and batch re-encryption
func (b *C4ghBackend) pathContainers() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Project",
				},
			},
			"batch": {
				Type:        framework.TypeString,
				Description: "Base64 encoded JSON indicating headers to be re-encrypted. Must be in the request body for update operations.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:        "Batch",
					Description: "Used in the batch request",
					Value:       "b64encoded JSON",
				},
			},
			"service": {
				Type:        framework.TypeNameString,
				Description: "Service that requests the file, matches the whitelist service name. Must be in the request body for update operations.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:        "Service",
					Description: "Used in the batch request",
					Value:       "service-name",
				},
			},
			"key": {
				Type:        framework.TypeNameString,
				Description: "Name of the whitelisted key the service wants to use. Must be in the request body for update operations.",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:        "Key",
					Description: "Used in the batch request",
					Value:       "key-name",
				},
			},
			"versions": {
				Type:        framework.TypeBool,
				Description: "Return the latest versions of headers instead of re-encrypting them",
				Default:     false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:    b.pathFilesBatchWrite,
				Summary:     "Batch re-encrypt headers or get their latest versions",
				Description: pathContainersUpdateOperationDescription,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathContainersList,
				Summary:  "List all containers for a project",
			},
		},
		HelpSynopsis:    pathContainersHelpSynopsis,
		HelpDescription: pathContainersHelpDescription,
	}
}

// pathListFiles List containers and files for a container
func (b *C4ghBackend) pathListFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Project",
				},
			},
			"container": {
				Type:        framework.TypeString,
				Description: "Container / bucket the header belongs in",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name: "Container",
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathFilesList,
				Summary:  "List all headers in a container",
			},
		},
		HelpSynopsis:    pathFilesListHelpSynopsis,
		HelpDescription: pathFilesListHelpDescription,
	}
}

// pathContainersList list all containers for a project
func (b *C4ghBackend) pathContainersList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	listPath := fmt.Sprintf("files/%s/", project)

	entries, err := req.Storage.List(ctx, listPath)

	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathFilesList list all headers uploaded to a specific project
func (b *C4ghBackend) pathFilesList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	listPath := fmt.Sprintf("files/%s/%s/", project, container)
	entries, err := req.Storage.List(ctx, listPath)

	if err != nil {
		return nil, err
	}

	decodedEntries := make([]string, len(entries))
	for i, entry := range entries {
		key, err := base64.StdEncoding.DecodeString(entry)
		if err != nil {
			return nil, err
		}
		decodedEntries[i] = string(key)
	}

	return logical.ListResponse(decodedEntries), nil
}

// pathFilesRead Read a re-encrypted header
func (b *C4ghBackend) pathFilesRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	service := d.Get("service").(string)
	keyName := d.Get("key").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	file64 := base64.StdEncoding.EncodeToString([]byte(file))

	var useProject string
	owner := d.Get("owner").(string)
	if owner != "" {
		// Check if the project exists in whitelist
		// listPath := fmt.Sprintf("sharing/%s/%s/%s", owner, container, project)
		rawKeyEntry, err := req.Storage.Get(ctx, "sharing/"+owner+"/"+container+"/"+project)
		if err != nil {
			return nil, err
		}
		if rawKeyEntry == nil {
			return logical.ErrorResponse("no whitelisted project found"), nil
		}
		useProject = owner
	} else {
		useProject = project
	}

	return b.readFile(ctx, req, useProject, container, file64, service, keyName, project)
}

// pathFilesExistenceCheck check a file exists by trying to read it
// this to decide if the operation is POST or PUT
// see https://github.com/hashicorp/vault/issues/22173#issuecomment-1762962763
func (b *C4ghBackend) pathFilesExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	resp, err := b.pathFilesRead(ctx, req, d)

	return resp != nil && !resp.IsError(), err
}

// pathFilesBatchWrite batch re-encrypt headers
func (b *C4ghBackend) pathFilesBatchWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	service := d.Get("service").(string)
	keyName := d.Get("key").(string)
	batch := d.Get("batch").(string)
	versions := d.Get("versions").(bool)
	batch64, err := base64.StdEncoding.DecodeString(batch)
	if err != nil {
		return nil, err
	}

	var batchJSON map[string][]string
	err = json.Unmarshal(batch64, &batchJSON)
	if err != nil {
		return nil, err
	}

	// Final response
	resp := &logical.Response{}
	resp.Data = make(map[string]any)

	g, ctx := errgroup.WithContext(ctx)

	// Results per container are sent to the following goroutine via this channel
	respc := make(chan batchResult)
	wait := make(chan any)

	go func() {
		for next := range respc {
			resp.Data[next.container] = next.responses

			for missing := range next.missing {
				resp.AddWarning(fmt.Sprintf("No matches found for %s in container %s", missing, next.container))
			}
		}

		wait <- nil
	}()

	for container := range batchJSON {
		g.Go(func() error {
			notFound := make(map[string]bool)
			listPath := fmt.Sprintf("files/%s/%s/", project, container)
			entries, err := req.Storage.List(ctx, listPath)
			if err != nil {
				return err
			}
			for _, pattern := range batchJSON[container] {
				notFound[pattern] = true
			}

			resps := map[string]any{}
			for _, entry := range entries {
				decodedEntry, err := base64.StdEncoding.DecodeString(entry)
				if err != nil {
					return err
				}
				for _, pattern := range batchJSON[container] {
					match, err := doublestar.Match(pattern, string(decodedEntry))
					if err != nil {
						return err
					}

					if match && versions {
						delete(notFound, pattern)

						var result fileEntryMap
						if err := b.decodeFile(ctx, req, project, container, entry, &result); err != nil {
							return err
						}
						resps[string(decodedEntry)] = result.LatestVersion

						break
					}

					if match {
						delete(notFound, pattern)

						nextResp, err := b.readFile(ctx, req, project, container, entry, service, keyName, project)
						if err != nil {
							return err
						}
						if nextResp == nil {
							return fmt.Errorf("failed to read %s with service %s and key %s", listPath, service, keyName)
						}
						if nextResp.IsError() {
							return nextResp.Error()
						}

						resps[string(decodedEntry)] = nextResp.Data

						break
					}
				}
			}

			select {
			case respc <- batchResult{container: container, responses: resps, missing: maps.Keys(notFound)}:
			case <-ctx.Done():
				return ctx.Err()
			}

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	close(respc)
	<-wait

	return resp, nil
}

func (b *C4ghBackend) decodeFile(
	ctx context.Context,
	req *logical.Request,
	project, container, file string,
	result *fileEntryMap,
) error {
	filePath := fmt.Sprintf("files/%s/%s/%s", project, container, file)
	entry, err := req.Storage.Get(ctx, filePath)
	if err != nil {
		return err
	}
	if entry == nil {
		return nil
	}

	return entry.DecodeJSON(&result)
}

func (b *C4ghBackend) readFile(
	ctx context.Context,
	req *logical.Request,
	owner, container, file, service, keyName, project string,
) (*logical.Response, error) {
	// Open old headers
	var result fileEntryMap
	if err := b.decodeFile(ctx, req, owner, container, file, &result); err != nil {
		return nil, err
	}
	if result.LatestVersion == 0 { // No file found
		return nil, nil
	}

	// Get the policy
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    owner,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("No project encryption key available."), nil
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	// Get the allowed receivers' key from whitelist
	listPath := fmt.Sprintf("whitelist/%s/%s/%s", project, service, keyName)
	rawKeyEntry, err := req.Storage.Get(ctx, listPath)
	if err != nil {
		return nil, err
	}
	if rawKeyEntry == nil {
		return logical.ErrorResponse("no whitelisted key found"), nil
	}

	var keyEntry transitWhitelistEntry
	if err := rawKeyEntry.DecodeJSON(&keyEntry); err != nil {
		return nil, err
	}

	pubkey, err := base64.StdEncoding.DecodeString(keyEntry.Key)
	if err != nil {
		return nil, err
	}
	var receiver [chacha20poly1305.KeySize]byte
	copy(receiver[:], pubkey)

	for k, v := range result.Headers {
		decHeader, err := base64.StdEncoding.DecodeString(v.Header)
		if err != nil {
			fmt.Println("decode error:", err)

			return logical.ErrorResponse("Incorrectly formed header version %s.", k), nil
		}
		binaryHeader, err := headers.ReadHeader(bytes.NewReader(decHeader))
		if err != nil {
			return nil, err
		}

		pkey, err := p.GetKey(nil, v.Keyversion, p.KeySize)
		if err != nil {
			return nil, err
		}
		if pkey == nil {
			return logical.ErrorResponse("Key version %d not found.", v.Keyversion), nil
		}

		// Copy the key to a fixed length array since NewHeader is picky
		var privkey [chacha20poly1305.KeySize]byte
		keys.PrivateKeyToCurve25519(&privkey, pkey)

		newBinaryHeader, err := headers.ReEncryptHeader(binaryHeader, privkey, [][chacha20poly1305.KeySize]byte{receiver})
		if err != nil {
			return nil, err
		}

		result.Headers[k] = reencryptFileEntry{
			Header:     base64.StdEncoding.EncodeToString(newBinaryHeader),
			Keyversion: v.Keyversion,
			Added:      v.Added,
		}
	}

	return &logical.Response{
		Data: map[string]any{
			"headers":        result.Headers,
			"latest_version": result.LatestVersion,
		},
	}, nil
}

// pathFilesWrite write a header encrypted with a key known to the plugin
func (b *C4ghBackend) pathFilesWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	header := d.Get("header").(string)

	file64 := base64.StdEncoding.EncodeToString([]byte(file))

	var useProject string
	owner := d.Get("owner").(string)
	if owner != "" {
		// Check if the project exists in whitelist
		listPath := fmt.Sprintf("sharing/%s/%s/%s", owner, container, project)
		rawKeyEntry, err := req.Storage.Get(ctx, listPath)
		if err != nil {
			return nil, err
		}
		if rawKeyEntry == nil {
			return logical.ErrorResponse("no whitelisted project found"), logical.ErrInvalidRequest
		}
		useProject = owner
	} else {
		useProject = project
	}

	// Get the policy
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    useProject,
	}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("encryption key not found"), logical.ErrInvalidRequest
	}
	if !b.System().CachingDisabled() {
		p.Lock(false)
	}
	defer p.Unlock()

	fmt.Println("Fetching key")
	key, err := p.GetKey(nil, p.LatestVersion, p.KeySize)
	if err != nil {
		return nil, err
	}

	var privkey [chacha20poly1305.KeySize]byte
	keys.PrivateKeyToCurve25519(&privkey, key)

	fmt.Println("Decoding base64 header")
	headerBytes, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}

	// Try decrypting the header with the latest key
	fmt.Println("Trying to read the header")
	headerReader := bytes.NewReader(headerBytes)
	binaryHeader, err := headers.ReadHeader(headerReader)
	if err != nil {
		return nil, err
	}

	fmt.Println("Trying to decrypt the binary header reader")
	buffer := bytes.NewBuffer(binaryHeader)
	headerParsed, err := headers.NewHeader(buffer, privkey)
	if err != nil {
		return nil, err
	}

	if headerParsed == nil {
		return logical.ErrorResponse("Could not decrypt header with the latest private key."), nil
	}

	dataEncryptionParametersHeaderPackets, err := headerParsed.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		return nil, err
	}

	firstDataEncryptionParametersHeader := (*dataEncryptionParametersHeaderPackets)[0]
	for _, dataEncryptionParametersHeader := range *dataEncryptionParametersHeaderPackets {
		if dataEncryptionParametersHeader.GetPacketType() != firstDataEncryptionParametersHeader.GetPacketType() {
			return logical.ErrorResponse("different data encryption methods are not supported"), nil
		}
	}

	// Header was successfully decrypted, add it to the database
	newHeader := reencryptFileEntry{
		Header:     header, // header stored in base64 format
		Keyversion: p.LatestVersion,
		Added:      time.Now(),
	}

	// Get old headers if they exist
	filePath := fmt.Sprintf("files/%s/%s/%s", useProject, container, file64)
	oldEntry, err := req.Storage.Get(ctx, filePath)
	if err != nil {
		return nil, err
	}

	var entry *logical.StorageEntry
	if oldEntry == nil {
		entry, err = logical.StorageEntryJSON(filePath, fileEntryMap{
			Headers:       map[string]reencryptFileEntry{"1": newHeader},
			LatestVersion: 1,
		})
	} else {
		var files fileEntryMap
		if err = oldEntry.DecodeJSON(&files); err != nil {
			return nil, err
		}
		files.Headers[strconv.Itoa(files.LatestVersion+1)] = newHeader
		entry, err = logical.StorageEntryJSON(filePath, fileEntryMap{
			Headers:       files.Headers,
			LatestVersion: files.LatestVersion + 1,
		})
	}

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathFilesUpdate write a header encrypted with a key known to the plugin
func (b *C4ghBackend) pathFilesUpdate(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	return b.pathFilesWrite(ctx, req, d)
}

// pathFilesDelete delete an encryption header from storage
func (b *C4ghBackend) pathFilesDelete(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	file64 := base64.StdEncoding.EncodeToString([]byte(file))
	headerPath := fmt.Sprintf("files/%s/%s/%s", project, container, file64)

	err := req.Storage.Delete(ctx, headerPath)

	if err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	pathFilesHelpSynopsis    = `Implements an encrypted transit service that stores and re-encrypts crypt4gh file headers on demand`
	pathFilesHelpDescription = `
This path allows you to add file headers that are encrypted with a public key known
to this transit service. These headers can then be downloaded re-encrypted
with a whitelisted key, or deleted permanently using this path.
`
	pathContainersHelpSynopsis = `
Re-encrypts multiple headers at the same time, returns the latest version
number of each file header, or lists which containers / buckets contain uploaded headers
`
	pathContainersHelpDescription = `
This path allows you to download re-encrypted headers in batches. Listing order of buckets is not specified.
`
	pathContainersUpdateOperationDescription = "The request body must be a JSON object:\n```" +
		`
{
"batch":   "base64 encoded JSON",
"service": "service-name",
"key":     "key-name"
}
` + "```\nAnd the batch field must be a JSON file in the following format:\n```" +
		`
{
"container": ["object"],
"another-container": ["object", "another-object"]
}
`
	pathFilesListHelpSynopsis           = `List the uploaded headers for a specific project in a specific container / bucket`
	pathFilesListHelpDescription        = `File header listing order is not specified`
	pathFilesUpdateOperationDescription = "The header must have been encrypted with the project's public key.\nThe request JSON is in the format:\n```" +
		`
{
	"header": "b64encoded header",
	"owner": "owner"
}
` + "```\nwith **owner** being an optional field."
)
