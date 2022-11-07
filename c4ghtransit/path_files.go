package c4ghtransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/keysutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
)

type reencryptFileEntry struct {
	Header     string `json:"header"`
	Keyversion int    `json:"keyversion"`
	Added      string `json:"added"`
}

type reencryptFileReturn struct {
	Header     string `json:"header"`
	Keyversion int    `json:"keyversion"`
}

// pathKeys extends the Vault API with a "/keys"
// endpoint.
func (b *c4ghTransitBackend) pathFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
			},
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the file the uploaded header belongs to",
				Required:    true,
			},
			"header": {
				Type:        framework.TypeString,
				Description: "Base64 encoded string of an encrypted header encrypted with a key known to the c4gh-transit plugin",
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

// List stored file headers
func (b *c4ghTransitBackend) pathListFiles() *framework.Path {
	return &framework.Path{
		Pattern: "files/" + framework.GenericNameRegex("project"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that the header is uploaded for",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathFilesList,
			},
		},
		HelpSynopsis:    pathFilesHelpSynopsis,
		HelpDescription: pathFilesHelpDescription,
	}
}

// List all headers uploaded to a specific project
func (b *c4ghTransitBackend) pathFilesList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	listPath := fmt.Sprintf("files/%s", project)
	entries, err := req.Storage.List(ctx, listPath)

	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// Read a re-encrypted header
func (b *c4ghTransitBackend) pathFilesRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	name := d.Get("name").(string)

	// Open the old header
	filePath := fmt.Sprintf("files/%s/%s", project, name)
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

	decHeader := make([]byte, base64.StdEncoding.DecodedLen(len(result.Header)))
	n, err := base64.StdEncoding.Decode(decHeader, []byte(result.Header))
	if err != nil {
		fmt.Println("decode error:", err)
		return logical.ErrorResponse(("Incorrectly formed header.")), nil
	}
	decHeader = decHeader[:n]
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
	pkey, err := p.GetKey(nil, result.Keyversion, p.KeySize)
	if err != nil {
		return nil, err
	}
	if pkey == nil {
		return logical.ErrorResponse("Latest key not found."), nil
	}

	// Copy the key to a fixed length array since NewHeader is picky
	var key [32]byte
	copy(key[:], pkey[:32])

	buffer := bytes.NewBuffer(binaryHeader)
	header, err := headers.NewHeader(buffer, key)
	if err != nil {
		return nil, err
	}

	dataEncryptionParametersHeaderPackets, err := header.GetDataEncryptionParameterHeaderPackets()
	if err != nil {
		return nil, err
	}
	// dataEditList, err := header.GetDataEditListHeaderPacket()
	// if err != nil {
	// 	return nil, err
	// }

	firstDataEncryptionParametersHeader := (*dataEncryptionParametersHeaderPackets)[0]
	for _, dataEncryptionParametersHeader := range *dataEncryptionParametersHeaderPackets {
		if dataEncryptionParametersHeader.GetPacketType() != firstDataEncryptionParametersHeader.GetPacketType() {
			return logical.ErrorResponse("different data encryption methods are not supported"), nil
		}
	}
	encryptedSegmentSize := firstDataEncryptionParametersHeader.EncryptedSegmentSize

	// Create the new encrypted header packet
	encHeaderPacket := headers.DataEncryptionParametersHeaderPacket{
		EncryptedSegmentSize: encryptedSegmentSize,
		PacketType:           headers.PacketType{PacketType: headers.DataEncryptionParameters},
		DataEncryptionMethod: headers.ChaCha20IETFPoly1305,
		DataKey:              firstDataEncryptionParametersHeader.DataKey,
	}

	// Get the allowed receivers from whitelist
	keylist, err := req.Storage.List(ctx, "whitelist/"+project)
	if err != nil {
		return nil, err
	}

	arrln := len(keylist)
	receivers := make([][32]byte, arrln)

	var keyEntry transitWhitelistEntry
	for index, element := range keylist {
		entry, err := req.Storage.Get(ctx, "whitelist/"+project+"/"+element)
		if err != nil {
			receivers = nil
			return nil, err
		}

		if err := entry.DecodeJSON(&keyEntry); err != nil {
			receivers = nil
			return nil, err
		}
		receivers[index], err = keys.ReadPublicKey(strings.NewReader(keyEntry.Key))
		if err != nil {
			receivers = nil
			return nil, err
		}
	}

	headerPackets := make([]headers.HeaderPacket, 0)

	_, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	for _, readerPublicKey := range receivers {
		headerPackets = append(headerPackets, headers.HeaderPacket{
			WriterPrivateKey:       privateKey,
			ReaderPublicKey:        readerPublicKey,
			HeaderEncryptionMethod: headers.X25519ChaCha20IETFPoly1305,
			EncryptedHeaderPacket:  encHeaderPacket,
		})
	}

	var magicNumber [8]byte
	copy(magicNumber[:], headers.MagicNumber)

	newHeader := headers.Header{
		MagicNumber:       magicNumber,
		Version:           headers.Version,
		HeaderPacketCount: uint32(len(headerPackets)),
		HeaderPackets:     headerPackets,
	}

	newBinaryHeader, err := newHeader.MarshalBinary()
	if err != nil {
		return nil, err
	}

	newEncodedHeader := make([]byte, base64.StdEncoding.EncodedLen(len(newBinaryHeader)))
	base64.StdEncoding.Encode(newEncodedHeader, newBinaryHeader)

	return &logical.Response{
		Data: map[string]interface{}{
			"header":     newEncodedHeader,
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
	name := d.Get("name").(string)
	header := d.Get("header").(string)

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

	fmt.Println("Fetching key")
	key, err := p.GetKey(nil, p.LatestVersion, p.KeySize)
	if err != nil {
		return nil, err
	}
	var privkey [32]byte
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

	if header_parsed != nil {
		return logical.ErrorResponse("Could not decrypt header with the latest private key."), nil
	}

	t := time.Now()
	created, err := fmt.Println(t.String())

	// Header was successfully decrypted, add it to the database
	filePath := fmt.Sprintf("files/%s/%s", project, name)
	entry, err := logical.StorageEntryJSON(filePath, map[string]interface{}{
		"header":     header, // header stored in base64 format
		"keyversion": p.LatestVersion,
		"added":      created,
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
	name := d.Get("name").(string)
	headerPath := fmt.Sprintf("files/%s/%s", project, name)

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
	pathFilesListHelpSynopsis    = `List the uploaded headers for a specific project`
	pathFilesListHelpDescription = `File header listing order is not specified`
)
