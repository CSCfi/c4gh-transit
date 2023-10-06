package c4ghtransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
	"golang.org/x/crypto/chacha20poly1305"
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

// pathFiles extends fault with a c4ghtransit/files endpoint for storing headers encrypted with keys stored in vault
func (b *C4ghBackend) pathFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/" + framework.MatchAllRegex("file"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeString,
				Description: "Container or bucket that the file belongs to",
				Required:    true,
			},
			"file": {
				Type:        framework.TypeString,
				Description: "Full object path of the file the uploaded header belongs to",
				Required:    true,
			},
			"header": {
				Type:        framework.TypeString,
				Description: "Base64 encoded string of an encrypted header encrypted with a key known to the c4gh-transit plugin",
				Required:    true,
			},
			"service": {
				Type:        framework.TypeNameString,
				Description: "Service that requests the file, matches the whitelist service name",
				Required:    true,
			},
			"key": {
				Type:        framework.TypeNameString,
				Description: "Name of whitelisted key the service wants to use",
				Required:    true,
			},
			"owner": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container (if the container is shared)",
				Default:     "",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFilesRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathFilesWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathFilesUpdate,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathFilesDelete,
			},
		},
		HelpSynopsis:    pathFilesHelpSynopsis,
		HelpDescription: pathFilesHelpDescription,
	}
}

// List stored file containers
func (b *C4ghBackend) pathContainers() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
			},
			"batch": {
				Type:        framework.TypeString,
				Description: "JSON instructing which headers should be returned",
				Required:    true,
			},
			"service": {
				Type:        framework.TypeNameString,
				Description: "Service that requests the file, matches the whitelist service name",
				Required:    true,
			},
			"key": {
				Type:        framework.TypeNameString,
				Description: "Name of whitelisted key the service wants to use",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathFilesBatchRead,
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathContainersList,
			},
		},
		HelpSynopsis:    pathContainersHelpSynopsis,
		HelpDescription: pathContainersHelpDescription,
	}
}

// List containers
func (b *C4ghBackend) pathListFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeString,
				Description: "Container / bucket the header belongs in",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathFilesList,
			},
		},
		HelpSynopsis:    pathFilesListHelpSynopsis,
		HelpDescription: pathFilesListHelpDescription,
	}
}

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

// List all headers uploaded to a specific project
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

// Read a re-encrypted header
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

// Read a re-encrypted header
func (b *C4ghBackend) pathFilesBatchRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	service := d.Get("service").(string)
	keyName := d.Get("key").(string)
	batch := d.Get("batch").(string)
	batch64, err := base64.StdEncoding.DecodeString(batch)
	if err != nil {
		return nil, err
	}

	var batchJSON map[string][]string
	err = json.Unmarshal(batch64, &batchJSON)
	if err != nil {
		return nil, err
	}

	resp := &logical.Response{}
	resp.Data = make(map[string]interface{})
	for container := range batchJSON {
		listPath := fmt.Sprintf("files/%s/%s/", project, container)
		entries, err := req.Storage.List(ctx, listPath)
		if err != nil {
			return nil, err
		}

		found := make(map[string]bool)
		for _, pattern := range batchJSON[container] {
			found[pattern] = false
		}

		resps := map[string]interface{}{}
		for _, entry := range entries {
			decodedEntry, err := base64.StdEncoding.DecodeString(entry)
			if err != nil {
				return nil, err
			}
			for _, pattern := range batchJSON[container] {
				match, err := filepath.Match(pattern, string(decodedEntry))
				if err != nil {
					return nil, err
				}
				if match {
					found[pattern] = true
					nextResp, err := b.readFile(ctx, req, project, container, entry, service, keyName, project)
					if err != nil {
						return nil, err
					}
					if nextResp.IsError() {
						return nextResp, nil
					}
					if nextResp != nil {
						resps[string(decodedEntry)] = nextResp.Data
					}

					break
				}
			}
		}

		for f := range found {
			if !found[f] {
				resp.AddWarning(fmt.Sprintf("No matches found for %s in container %s", f, container))
			}
		}

		resp.Data[container] = resps
	}

	return resp, nil
}

func (b *C4ghBackend) readFile(
	ctx context.Context,
	req *logical.Request,
	owner, container, file, service, keyName, project string,
) (*logical.Response, error) {
	// Open old headers
	filePath := fmt.Sprintf("files/%s/%s/%s", owner, container, file)
	entry, err := req.Storage.Get(ctx, filePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result fileEntryMap
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
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
		Data: map[string]interface{}{
			"headers":        result.Headers,
			"latest_version": result.LatestVersion,
		},
	}, nil
}

// Write a header encrypted with a key known to the plugin
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

// Write a header encrypted with a key known to the plugin
func (b *C4ghBackend) pathFilesUpdate(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	return b.pathFilesWrite(ctx, req, d)
}

// Delete an encryption header from storage
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
Re-encrypts multiple headers at the same time, and lists the containers / buckets into which headers have been uploaded
`
	pathContainersHelpDescription = `
This path allows you to download re-encrypted headers in batches. Listing order of buckets is not specified.
`
	pathFilesListHelpSynopsis    = `List the uploaded headers for a specific project in a specific container / bucket`
	pathFilesListHelpDescription = `File header listing order is not specified`
)
