package c4ghtransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
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

// pathFiles extends fault with a c4ghtransit/files endpoint for storing headers encrypted with keys stored in vault
func (b *c4ghTransitBackend) pathFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("container") + "/" + framework.MatchAllRegex("file"),
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
func (b *c4ghTransitBackend) pathListContainers() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathContainersList,
			},
		},
		HelpSynopsis:    pathContainerListHelpSynopsis,
		HelpDescription: pathContainerListHelpDescription,
	}
}

// List containers
func (b *c4ghTransitBackend) pathListFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("container") + "/?$",
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

func (b *c4ghTransitBackend) pathContainersList(
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
func (b *c4ghTransitBackend) pathFilesList(
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
func (b *c4ghTransitBackend) pathFilesRead(
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

	// Open the old header
	filePath := fmt.Sprintf("files/%s/%s/%s", project, container, file64)
	entry, err := req.Storage.Get(ctx, filePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result reencryptFileEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	decHeader, err := base64.StdEncoding.DecodeString(result.Header)
	if err != nil {
		fmt.Println("decode error:", err)
		return logical.ErrorResponse(("Incorrectly formed header.")), nil
	}
	binaryHeader, err := headers.ReadHeader(bytes.NewReader(decHeader))
	if err != nil {
		return nil, err
	}

	// Get the policy
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    project,
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
	pkey, err := p.GetKey(nil, result.Keyversion, p.KeySize)
	if err != nil {
		return nil, err
	}
	if pkey == nil {
		return logical.ErrorResponse("Key not found."), nil
	}

	// Copy the key to a fixed length array since NewHeader is picky
	var privkey [chacha20poly1305.KeySize]byte
	keys.PrivateKeyToCurve25519(&privkey, pkey)

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

	newBinaryHeader, err := headers.ReEncryptHeader(binaryHeader, privkey, [][chacha20poly1305.KeySize]byte{receiver})
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"header":     base64.StdEncoding.EncodeToString(newBinaryHeader),
			"keyversion": p.LatestVersion,
		},
	}, nil
}

// Write a header encrypted with a key known to the plugin
func (b *c4ghTransitBackend) pathFilesWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	header := d.Get("header").(string)

	file64 := base64.StdEncoding.EncodeToString([]byte(file))

	// Get the policy
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{
		Storage: req.Storage,
		Name:    project,
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
	header_bytes, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, err
	}

	// Try decrypting the header with the latest key
	fmt.Println("Trying to read the header")
	header_reader := bytes.NewReader(header_bytes)
	binary_header, err := headers.ReadHeader(header_reader)
	if err != nil {
		return nil, err
	}

	fmt.Println("Trying to decrypt the binary header reader")
	buffer := bytes.NewBuffer(binary_header)
	header_parsed, err := headers.NewHeader(buffer, privkey)
	if err != nil {
		return nil, err
	}

	if header_parsed == nil {
		return logical.ErrorResponse("Could not decrypt header with the latest private key."), nil
	}

	dataEncryptionParametersHeaderPackets, err := header_parsed.GetDataEncryptionParameterHeaderPackets()
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
	filePath := fmt.Sprintf("files/%s/%s/%s", project, container, file64)
	entry, err := logical.StorageEntryJSON(filePath, map[string]interface{}{
		"header":     header, // header stored in base64 format
		"keyversion": p.LatestVersion,
		"added":      time.Now(),
	})

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

// Write a header encrypted with a key known to the plugin
func (b *c4ghTransitBackend) pathFilesUpdate(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	return b.pathFilesWrite(ctx, req, d)
}

// Delete an encryption header from storage
func (b *c4ghTransitBackend) pathFilesDelete(
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
	pathFilesListHelpSynopsis        = `List the uploaded headers for a specific project in a specific container / bucket`
	pathFilesListHelpDescription     = `File header listing order is not specified`
	pathContainerListHelpSynopsis    = `List the containers / buckets into which headers have been uploaded`
	pathContainerListHelpDescription = `Listing order is not specified`
)
