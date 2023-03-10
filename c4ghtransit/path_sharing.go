package c4ghtransit

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	sharingStoragePath = "whitelist"
)

type transitSharingWhitelistEntry struct {
	id         string `json:"id"`         // Project ID for sharing
	idkeystone string `json:"idkeystone"` // Project name for sharing
}

// pathSharing adds functionality to whitelist specific projects with rights
// to ask for re-encrypted headers for specific files, folders or projects
func (b *c4ghTransitBackend) pathSharingContainers() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("container"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project that owns the container",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeNameString,
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
		HelpSynopsis:    pathSharingHelpSynopsis,
		HelpDescription: pathSharingHelpDescription,
	}
}

func (b *c4ghTransitBackend) pathSharingFiles() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("container") + "/" + framework.MatchAllRegex("file"),
		Fields: map[string]*framework.FieldSchema{
			"project": {
				Type:        framework.TypeLowerCaseString,
				Description: "Project id that is to be whitelisted",
				Required:    true,
			},
			"container": {
				Type:        framework.TypeNameString,
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
		HelpSynopsis:    pathFileSharingHelpSynopsis,
		HelpDescription: pathFileSharingHelpDescription,
	}
}

func (b *c4ghTransitBackend) pathSharingList() *framework.Path {
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

func (b *c4ghTransitBackend) pathSharingContainerList() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("container") + "/" + framework.MatchAllRegex("file"),
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

func (b *c4ghTransitBackend) pathSharingFileList() *framework.Path {
	return &framework.Path{
		Pattern: "sharing/" + framework.GenericNameRegex("project") + "/" + framework.GenericNameRegex("container") + "/" + framework.MatchAllRegex("file"),
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
func (b *c4ghTransitBackend) pathSharingListList(
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
func (b *c4ghTransitBackend) pathSharingContainerListList(
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
func (b *c4ghTransitBackend) pathSharingFileListList(
	ctx context.Context,
	req *logical.Request,
	d *framework.FieldData,
) (*logical.Response, error) {
	project := d.Get("project").(string)
	container := d.Get("container").(string)
	file := d.Get("file").(string)
	listPath := fmt.Sprintf("sharing/%s/%s/%s", project, container, file)
	entries, err := req.Storage.List(ctx, listPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// Read a whitelisted project details
func (b *c4ghTransitBackend) pathSharingRead(
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
			"id":         result.id,
			"idkeystone": result.idkeystone,
		},
	}, nil
}

// Add a project to container whitelist
func (b *c4ghTransitBackend) pathSharingWrite(
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
func (b *c4ghTransitBackend) pathSharingDelete(
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
func (b *c4ghTransitBackend) pathFileSharingRead(
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
			"id":         result.id,
			"idkeystone": result.idkeystone,
		},
	}, nil
}

// Add a whitelisted project for a file
func (b *c4ghTransitBackend) pathFileSharingWrite(
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
func (b *c4ghTransitBackend) pathFileSharingDelete(
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
This access will allow the project to whitleist a key for purposes of downloading, and fetch the project public key for purposes of uploaing.
`
	pathSharingListHelpSynopsis    = `List the whitelisted projects for specific project, container or file.`
	pathSharingListHelpDescription = `Whitelisted project order is not specified.`
)
