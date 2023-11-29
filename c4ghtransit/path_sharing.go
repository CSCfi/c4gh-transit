package c4ghtransit

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type transitSharingWhitelistEntry struct {
	ID         string `json:"id"`         // Project ID for sharing
	IDKeystone string `json:"idkeystone"` // Project name for sharing
}

// pathSharing adds functionality to whitelist specific projects with rights
// to ask for re-encrypted headers for specific files, folders or projects
func (b *C4ghBackend) pathSharingContainers() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeString,
				Description: "Container that is to be whitelisted",
				Required:    true,
			},
			"id": {
				Type:        framework.TypeNameString,
				Description: "Project id that is to be whitelisted",
				Required:    true,
			},
			"idkeystone": {
				Type:        framework.TypeString,
				Description: "Project id in keystone that is to be whitelisted",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSharingRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathSharingWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathSharingWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathSharingDelete,
			},
		},
		ExistenceCheck:  b.pathSharingExistenceCheck,
		HelpSynopsis:    pathSharingHelpSynopsis,
		HelpDescription: pathSharingHelpDescription,
	}
}

//nolint:unused
func (b *C4ghBackend) pathSharingFiles() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/" + framework.MatchAllRegex("file"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project id that is to be whitelisted",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeString,
				Description: "Container that is to be whitelisted",
				Required:    true,
			},
			"file": {
				Type:        framework.TypeString,
				Description: "File that is to be whitelisted",
				Required:    true,
			},
			"id": {
				Type:        framework.TypeNameString,
				Description: "Project id that is to be whitelisted",
				Required:    true,
			},
			"idkeystone": {
				Type:        framework.TypeString,
				Description: "Project id in keystone that is to be whitelisted",
				Required:    false,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathFileSharingRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathFileSharingWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathFileSharingWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathFileSharingDelete,
			},
		},
		ExistenceCheck:  b.pathSharingExistenceCheck,
		HelpSynopsis:    pathFileSharingHelpSynopsis,
		HelpDescription: pathFileSharingHelpDescription,
	}
}

func (b *C4ghBackend) pathSharingList() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSharingListList,
			},
		},
		HelpSynopsis:    pathSharingListHelpSynopsis,
		HelpDescription: pathSharingListHelpDescription,
	}
}

func (b *C4ghBackend) pathSharingContainerList() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeNameString,
				Description: "Container that is to be listed",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSharingContainerListList,
			},
		},
		HelpSynopsis:    pathSharingListHelpSynopsis,
		HelpDescription: pathSharingListHelpDescription,
	}
}

func (b *C4ghBackend) pathSharingFileList() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + GenericContainerNameRegex("container") + "/" + framework.MatchAllRegex("file") + "/?$",
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeNameString,
				Description: "Container that is to be listed",
				Required:    true,
			},
			"file": {
				Type:        framework.TypeString,
				Description: "File that is to be listed",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathSharingFileListList,
			},
		},
		HelpSynopsis:    pathSharingListHelpSynopsis,
		HelpDescription: pathSharingListHelpDescription,
	}
}

// List containers containing whitelist in project
func (b *C4ghBackend) pathSharingListList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	listPath := fmt.Sprintf("sharing/%s/", project)
	entries, err := req.Storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// List files containing whitelist entry in container
func (b *C4ghBackend) pathSharingContainerListList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	listPath := fmt.Sprintf("sharing/%s/%s/", project, container)
	entries, err := req.Storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// List whitelisted projects for a file
func (b *C4ghBackend) pathSharingFileListList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	listPath := fmt.Sprintf("sharing/%s/%s/%s/", project, container, file)
	entries, err := req.Storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// Read a whitelisted project details
func (b *C4ghBackend) pathSharingRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	id := d.Get("id").(string)
	entry, err := req.Storage.Get(ctx, "sharing/"+project+"/"+container+"/"+id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result transitSharingWhitelistEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":         result.ID,
			"idkeystone": result.IDKeystone,
		},
	}, nil
}

// check a sharing exists by trying to read it
// this to decide if the operation is POST or PUT
// see https://github.com/hashicorp/vault/issues/22173#issuecomment-1762962763
func (b *C4ghBackend) pathSharingExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	resp, err := b.pathSharingRead(ctx, req, d)

	return resp != nil && !resp.IsError(), err
}

// Add a project to container whitelist
func (b *C4ghBackend) pathSharingWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	id := d.Get("id").(string)
	idkeystone := d.Get("idkeystone").(string)

	keyPath := fmt.Sprintf("sharing/%s/%s/%s", project, container, id)

	entry, err := logical.StorageEntryJSON(keyPath, map[string]interface{}{
		"id":         id,
		"idkeystone": idkeystone,
	})

	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// Remove a project from container whitelist
func (b *C4ghBackend) pathSharingDelete(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	id := d.Get("id").(string)
	keyPath := fmt.Sprintf("sharing/%s/%s/%s", project, container, id)

	err := req.Storage.Delete(ctx, keyPath)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Read whitelisted project details for a file
//
//nolint:unused
func (b *C4ghBackend) pathFileSharingRead(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	id := d.Get("id").(string)

	entry, err := req.Storage.Get(ctx, "sharing/"+project+"/"+container+"/"+file+"/"+id)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result transitSharingWhitelistEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"id":         result.ID,
			"idkeystone": result.IDKeystone,
		},
	}, nil
}

// Add a whitelisted project for a file
//
//nolint:unused
func (b *C4ghBackend) pathFileSharingWrite(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	id := d.Get("id").(string)
	idkeystone := d.Get("idkeystone").(string)

	keyPath := fmt.Sprintf("sharing/%s/%s/%s/%s", project, container, file, id)

	entry, err := logical.StorageEntryJSON(keyPath, map[string]interface{}{
		"id":         id,
		"idkeystone": idkeystone,
	})

	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

// Remove a whitelisted project for a file
//
//nolint:unused
func (b *C4ghBackend) pathFileSharingDelete(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	id := d.Get("id").(string)

	keyPath := fmt.Sprintf("sharing/%s/%s/%s/%s", project, container, file, id)

	err := req.Storage.Delete(ctx, keyPath)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

const (
	pathSharingHelpSynopsis    = `Manages projects that are allowed to access whitelist, in addition to the project that owns the container`
	pathSharingHelpDescription = `
This path allows you to add projects to a whitelist, which specifies if they're allowed to access a container owned by you.
This access will allow the project to whitelist a key for purposes of downloading, and fetch the project public key for purposes of uploading.
`
	pathFileSharingHelpSynopsis    = `Manages project that are allowed to access whitelist on a file level, in addition to the project that owns the container`
	pathFileSharingHelpDescription = `
This path allows you to add projects to a whitelist, which specifies if they're allowed to access a file in a container owned by you.
This access will allow the project to whitelist a key for purposes of downloading, and fetch the project public key for purposes of uploaing.
`
	pathSharingListHelpSynopsis    = `List the whitelisted projects for specific project, container or file.`
	pathSharingListHelpDescription = `Whitelisted project order is not specified.`
)
