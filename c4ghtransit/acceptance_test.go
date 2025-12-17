package c4ghtransit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"testing"

	"github.com/CSCfi/vault-testing-stepwise/environments/docker"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
	"github.com/neicnordic/crypt4gh/streaming"
	"golang.org/x/crypto/chacha20poly1305"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"

	stepwise "github.com/CSCfi/vault-testing-stepwise"
)

const vaultImage = "hashicorp/vault:latest"

var (
	oldKey         string
	projectKey     string
	encryptedFiles = make(map[string][]byte)
	content        = "Hide your secrets in a bucket."
)

func TestBackupPath(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "bucket"
	path := "hidden-in-a-bucket.txt.c4gh"

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString),
			// Upload encrypt file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Download encrypted file, and confirm it can be decrypted
			testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName),
			// Read backup key project
			testC4ghStepwiseReadBackupKey(t, project),
			// Read backup files project
			testC4ghStepwiseReadBackupFile(t, project),
			// List backup keys find project
			testC4ghStepwiseReadBackuplist(t, "keys", project),
			// List backup files find project
			testC4ghStepwiseReadBackuplist(t, "files", project),
		},
	}
	stepwise.Run(t, simpleCase)
}

func TestHeaderWhitelistDecryption(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "bucket"
	path := "hidden-in-a-bucket.txt.c4gh"

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString),
			// Upload encrypt file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Download encrypted file, and confirm it can be decrypted
			testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName),
			// Delete Whitelist
			testC4ghStepwiseDeleteWhitelist(t, project, service, keyName),
			// Try to read file after whitelist should get empty response
			testC4hgStepwiseReadWhitelistFileFail(t, project, container, path, service, keyName),
		},
	}
	stepwise.Run(t, simpleCase)
}

func TestHeaderSharingLifecycle(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	otherPublicKey, otherPrivateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate the other crypt4gh key pair")
		t.Error(err)
	}
	otherPublicKeyString := base64.StdEncoding.EncodeToString(otherPublicKey[:])

	project := "my-project"
	otherProject := "other-project"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "sharedbucket"
	path := "shared-file.txt.c4gh"
	otherPath := "new-file-from-other.txt.c4gh"

	containerWithSpaces := "container with spaces"
	containerWithForbidden := "container$with[]forbidden@chars~"

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString),
			// Add the shared project key to the whitelist and confirm it exists
			testC4ghStepwiseWriteWhitelist(t, otherProject, service, keyName, otherPublicKeyString),
			testC4ghStepwiseReadWhitelist(t, otherProject, service, keyName, otherPublicKeyString),
			// Upload encrypt file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Download encrypted file, and confirm it can be decrypted
			testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName),
			// Test downloading before sharing
			testC4hgStepwiseReadShareFileFail(t, otherProject, container, path, service, keyName, project),
			// Share access to decryption
			testC4ghStepwiseWriteSharingWhitelist(t, project, container, otherProject, otherProject),
			// Check that the share went through
			testC4ghStepwiseReadSharingWhitelist(t, project, container, otherProject),
			// Test downloading again
			testC4ghStepwiseReadSharedFile(t, otherProject, container, path, otherPrivateKey, service, keyName, project),
			// Test uploading a file
			testC4ghStepwiseWriteSharedFile(t, otherProject, container, otherPath, project),
			// Test reading the file from the original project
			testC4ghStepwiseReadFile(t, project, container, otherPath, privateKey, service, keyName),
			// Remove access to decryption
			testC4ghStepwiseDeleteSharingWhitelist(t, project, container, otherProject),
			// Check the download fails again
			testC4hgStepwiseReadShareFileFail(t, otherProject, container, path, service, keyName, project),
			// Test that the sharing succeeds with a container with spaces in the name
			testC4ghStepwiseWriteSharingWhitelist(t, project, containerWithSpaces, otherProject, otherProject),
			testC4ghStepwiseReadSharingWhitelist(t, project, containerWithSpaces, otherProject),
			testC4ghStepwiseDeleteSharingWhitelist(t, project, containerWithSpaces, otherProject),
			// Test that the sharing fails with a container with forbidden characters in the name
			testC4ghStepwiseWriteSharingWhitelistFail(t, project, containerWithForbidden, otherProject, otherProject),
			// Not testing for failures with reads, as reads fail with an empty request
			testC4ghStepwiseDeleteSharingWhitelistFail(t, project, containerWithForbidden, otherProject),
		},
	}
	stepwise.Run(t, simpleCase)
}

func TestKeyRotateAndHeaderRewrap(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "bucket"
	path := "hidden-in-a-bucket.txt.c4gh"
	path2 := "hidden-in-a-bucket2.txt.c4gh"

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString),
			// Upload encrypt file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Rotate project key
			testC4ghStepwiseRotate(t, project),
			// Get the new project key
			testC4ghStepwiseReadKey(t, project),
			// Confirm file cannot be uploaded with old key
			testC4ghStepwiseWriteFileFail(t, project, container, path2),
			// Download encrypted file, and confirm it can be decrypted
			testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName),
			// Rewrap file header
			testC4ghStepwiseRewrap(t, project),
			// Download encrypted file, and confirm it can be decrypted
			testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName),
		},
	}
	stepwise.Run(t, simpleCase)
}

func TestHeaderVersoning(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "bucket"
	path := "hidden-in-a-bucket.txt.c4gh"
	badContent := "I am not uploaded correctly in sd connect"

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString),
			// Upload encrypt file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Upload same file with new content
			testC4ghStepwiseWriteFile(t, project, container, path, badContent),
			// Download encrypted file with old content after the newer content was not saved
			testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName),
			// Delete File
			testC4ghStepwiseDeleteFile(t, project, container, path, service, keyName),
			// Try to read delete file should get empty response
			testC4hgStepwiseReadFileFail(t, project, container, path, service, keyName),
		},
	}
	stepwise.Run(t, simpleCase)
}

func TestReadMultipleFileHeaders(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	project2 := "my-project-2"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "bucket"
	container2 := "bucket-2"
	container3 := "bucket-3"
	path := "dir/hidden-in-a-bucket.txt.c4gh"
	path2 := "hidden-in-a-bucket2.txt.c4gh"
	path3 := "hidden-in-a-bucket3.txt.c4gh"

	reference := map[string][]string{container: {path, path2}, container2: {}, container3: {path, path3}}
	batch := make(map[string][]string)
	batch[container] = []string{"*/*bucket.*", path2}
	batch[container2] = []string{"*bucket.*"}
	batch[container3] = []string{"**"}
	b, err := json.Marshal(batch)
	if err != nil {
		fmt.Println(err)

		return
	}

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Upload encrypted file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Upload another encrypted file
			testC4ghStepwiseWriteFile(t, project, container, path2),
			// Upload another encrypted file
			testC4ghStepwiseWriteFile(t, project, container, path3),
			// Upload another encrypted file
			testC4ghStepwiseWriteFile(t, project, container2, path),
			// Upload another encrypted file
			testC4ghStepwiseWriteFile(t, project, container3, path),
			// Upload another encrypted file
			testC4ghStepwiseWriteFile(t, project, container3, path3),
			// Create a project key
			testC4ghStepwiseWriteKey(t, project2),
			// Get the project key
			testC4ghStepwiseReadKey(t, project2),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project2, service, keyName, publicKeyString),
			// Upload encrypted file
			testC4ghStepwiseWriteFile(t, project2, container2, path2),
			// Download encrypted files, and confirm they can be decrypted
			testC4ghStepwiseReadFiles(t, project, base64.StdEncoding.EncodeToString(b), reference, privateKey, service, keyName),
		},
	}
	stepwise.Run(t, simpleCase)
}

func TestHeaderWithWhitespaceContainerAndForbidden(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      api.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("C4ghTransit", &mountOptions, vaultImage)

	publicKey, _, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	service := "fake-service"
	keyName := "fake-key-name"
	container := "bucket with spaces and 日本語"
	containerForbid := "bucket with spaces and forbidden []"
	path := "hidden-in-a-bucket.txt.c4gh"

	weirdNameCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps: []stepwise.Step{
			// Create a project key
			testC4ghStepwiseWriteKey(t, project),
			// Get the project key
			testC4ghStepwiseReadKey(t, project),
			// Add locally created pub key to the whitelist
			testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString),
			// Upload a file to a container that should succeed
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Upload a file to a container that should not succeed
			testC4ghStepwiseWriteFileFail(t, project, containerForbid, path),
		},
	}
	stepwise.Run(t, weirdNameCase)
}

func testC4ghStepwiseWriteKey(_ *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteKey",
		Operation: stepwise.WriteOperation,
		Data:      map[string]any{"flavor": "crypt4gh"},
		Path:      fmt.Sprintf("/keys/%s", project),
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseReadKey(t *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadKey",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/keys/%s", project),
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			var data struct {
				Keys          map[string]map[string]string `mapstructure:"keys"`
				LatestVersion int                          `mapstructure:"latest_version"`
				Name          string                       `mapstructure:"name"`
			}
			if err = mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}
			assert.Assert(t, cmp.Contains(resp.Data, "keys"), fmt.Sprintf("Response did not contain expected keys: %s", resp.Data))
			assert.Equal(t, data.Name, project, fmt.Sprintf("Project name mismatch: %s, %s", project, resp.Data))

			oldKey = projectKey
			projectKey = data.Keys[fmt.Sprintf("%d", data.LatestVersion)]["public_key_c4gh_64"]

			return nil
		},
	}
}

func decodeJSON(encodedString string) (map[string]any, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedString) // Converting data

	if err != nil {
		fmt.Println("Failed to Decode from base64", err)

		return nil, err
	}

	var decodedJSON map[string]any
	err = json.Unmarshal(bytes, &decodedJSON)
	if err != nil {
		fmt.Println("Failed to parse JSON", err)

		return nil, err
	}

	return decodedJSON, nil
}

func testC4ghStepwiseReadBackupKey(t *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadBackupKey",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/backup/keys/%s", project),
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			var data struct {
				Backup string `mapstructure:"backup"`
			}
			if err = mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}
			assert.Assert(t, cmp.Contains(resp.Data, "backup"), fmt.Sprintf("Response did not contain expected backup: %s", resp.Data))

			backupData, err := decodeJSON(data.Backup)
			if err != nil {
				return err
			}

			// we want to at least check the name of the contents
			var key struct {
				Name string `mapstructure:"name"`
			}
			if err = mapstructure.Decode(backupData["policy"], &key); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}

			assert.Equal(t, key.Name, project, fmt.Sprintf("Project name mismatch: %s", key))

			return nil
		},
	}
}

func testC4ghStepwiseReadBackuplist(t *testing.T, backupType string, project string) stepwise.Step {
	return stepwise.Step{
		Name:      fmt.Sprintf("testC4ghStepwiseReadBackuplist-%s", backupType),
		Operation: stepwise.ListOperation,
		Path:      fmt.Sprintf("/backup/%s", backupType),
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}

			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			var data struct {
				Keys []any `mapstructure:"keys"`
			}
			if err = mapstructure.Decode(resp.Data, &data); err != nil {
				return fmt.Errorf("failed decoding to mapstructure")
			}

			// files listing has a different way of styling the listing
			// thus we format for that
			projectString := project
			if backupType == "files" {
				projectString = fmt.Sprintf("%s/", project)
			}

			assert.Assert(t, cmp.Contains(data.Keys, projectString), fmt.Sprintf("Response did not contain expected project: %s", data))

			return err
		},
	}
}

func testC4ghStepwiseWriteWhitelist(_ *testing.T, project string, service string, keyName string, publicKey string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteWhitelist",
		Operation: stepwise.WriteOperation,
		Data:      map[string]any{"flavor": "crypt4gh", "pubkey": publicKey},
		Path:      fmt.Sprintf("/whitelist/%s/%s/%s", project, service, keyName),
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseReadWhitelist(t *testing.T, project string, service string, keyName string, publicKey string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadWhitelist",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/whitelist/%s/%s/%s", project, service, keyName),
		Assert: func(resp *api.Secret, err error) error {
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}
			assert.Equal(t, resp.Data["key"], publicKey, fmt.Sprintf("Response did not contain expected key: %s", resp.Data))
			assert.Equal(t, resp.Data["project"], project, fmt.Sprintf("Response did not contain expected project: %s", resp.Data))
			assert.Equal(t, resp.Data["service"], service, fmt.Sprintf("Response did not contain expected service: %s", resp.Data))
			assert.Equal(t, resp.Data["name"], keyName, fmt.Sprintf("Response did not contain expected key name: %s", resp.Data))

			return err
		},
	}
}

func testC4ghStepwiseWriteSharingWhitelist(_ *testing.T, project string, container string, otherProject string, otherProjectID string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteSharingWhitelist",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		GetData: func() (map[string]any, error) {
			return map[string]any{
				"id":         otherProject,
				"idkeystone": otherProjectID,
			}, nil
		},
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseWriteSharingWhitelistFail(_ *testing.T, project string, container string, otherProject string, otherProjectID string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteSharingWhitelistFail",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		GetData: func() (map[string]any, error) {
			return map[string]any{
				"id":         otherProject,
				"idkeystone": otherProjectID,
			}, nil
		},
		Assert: func(_ *api.Secret, err error) error {
			if err == nil {
				return fmt.Errorf("function should've failed")
			}

			return nil
		},
	}
}

func testC4ghStepwiseReadSharingWhitelist(t *testing.T, project string, container string, otherProject string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadSharingWhitelist",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		BodyData: map[string][]string{
			"id": {otherProject},
		},
		Assert: func(resp *api.Secret, err error) error {
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}
			assert.Equal(t, resp.Data["id"], otherProject, fmt.Sprintf("Response did not contain expected project id: %s", resp.Data))
			assert.Equal(t, resp.Data["idkeystone"], otherProject, fmt.Sprintf("Response did not contain expected project keystone id: %s", resp.Data))

			return err
		},
	}
}

func testC4ghStepwiseDeleteSharingWhitelist(_ *testing.T, project string, container string, otherProject string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseDeleteSharingWhitelist",
		Operation: stepwise.DeleteOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		BodyData: map[string][]string{
			"id": {otherProject},
		},
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseDeleteSharingWhitelistFail(_ *testing.T, project string, container string, otherProject string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseDeleteSharingWhitelistFail",
		Operation: stepwise.DeleteOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		BodyData: map[string][]string{
			"id": {otherProject},
		},
		Assert: func(_ *api.Secret, err error) error {
			if err == nil {
				return fmt.Errorf("function should've failed")
			}

			return nil
		},
	}
}

func testC4ghStepwiseWriteFile(_ *testing.T, project, container, path string, otherContent ...string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteFile",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		GetData: func() (map[string]any, error) {
			byteContent := []byte(content)
			if len(otherContent) > 0 {
				byteContent = []byte(otherContent[0])
			}
			encryptedHeader, encryptedBody, err := encryptFile(projectKey, byteContent)
			if err != nil {
				fmt.Println("Failed encrypting file: ", err)

				return nil, err
			}
			if len(otherContent) == 0 {
				encryptedFiles[project+"/"+container+"/"+path] = encryptedBody
			}

			return map[string]any{"header": base64.StdEncoding.EncodeToString(encryptedHeader)}, nil
		},
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseWriteSharedFile(_ *testing.T, project, container, path string, owner string, otherContent ...string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteSharedFile",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		GetData: func() (map[string]any, error) {
			byteContent := []byte(content)
			if len(otherContent) > 0 {
				byteContent = []byte(otherContent[0])
			}
			encryptedHeader, encryptedBody, err := encryptFile(projectKey, byteContent)
			if err != nil {
				fmt.Println("Failed encrypting file: ", err)

				return nil, err
			}
			if len(otherContent) == 0 {
				encryptedFiles[owner+"/"+container+"/"+path] = encryptedBody
			}

			return map[string]any{
				"header": base64.StdEncoding.EncodeToString(encryptedHeader),
				"owner":  owner,
			}, nil
		},
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseReadFile(t *testing.T, project string, container string, path string,
	privateKey [chacha20poly1305.KeySize]byte, service string, keyName string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadFile",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		BodyData: map[string][]string{
			"service": {service},
			"key":     {keyName},
		},
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}
			var data struct {
				Headers       map[string]map[string]string `mapstructure:"headers"`
				LatestVersion int                          `mapstructure:"latest_version"`
			}
			if err := mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}
			var decryptedFile []byte
			version := data.LatestVersion
			for {
				header := data.Headers[strconv.Itoa(version)]["header"]
				decryptedFile, err = decryptFile(header, encryptedFiles[project+"/"+container+"/"+path], privateKey)
				if err == nil {
					break
				}
				version--
				if version == 0 {
					fmt.Println("Error decrypting file: ", err)

					return err
				}
			}
			var decryptedFileString = string(decryptedFile)
			assert.Equal(t, decryptedFileString, content, "Decrypted file and original content don't match")

			return nil
		},
	}
}

func testC4ghStepwiseReadSharedFile(t *testing.T, project string, container string, path string, privateKey [chacha20poly1305.KeySize]byte, service string, keyName string, owner string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadSharedFile",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		BodyData: map[string][]string{
			"service": {service},
			"key":     {keyName},
			"owner":   {owner},
		},
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}
			var data struct {
				Headers       map[string]map[string]string `mapstructure:"headers"`
				LatestVersion int                          `mapstructure:"latest_version"`
			}
			if err := mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}
			var decryptedFile []byte
			version := data.LatestVersion
			for {
				header := data.Headers[strconv.Itoa(version)]["header"]
				decryptedFile, err = decryptFile(header, encryptedFiles[owner+"/"+container+"/"+path], privateKey)
				if err == nil {
					break
				}
				version--
				if version == 0 {
					fmt.Println("Error decrypting file: ", err)

					return err
				}
			}
			var decryptedFileString = string(decryptedFile)
			assert.Equal(t, decryptedFileString, content, "Decrypted file and original content don't match")

			return nil
		},
	}
}

func testC4hgStepwiseReadShareFileFail(_ *testing.T, project string, container string, path string, service string, keyName string, owner string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadSharedFileFail",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		BodyData: map[string][]string{
			"service": {service},
			"key":     {keyName},
			"owner":   {owner},
		},
		Assert: func(_ *api.Secret, err error) error {
			if err == nil {
				return fmt.Errorf("function should've failed")
			}

			return nil
		},
	}
}

func testC4ghStepwiseReadFiles(t *testing.T, project, batch string, reference map[string][]string,
	privateKey [chacha20poly1305.KeySize]byte, service, keyName string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadFiles",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s", project),
		Data:      map[string]any{"batch": batch, "service": service, "key": keyName},
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			for refKey := range reference {
				assert.Assert(t, cmp.Contains(resp.Data, refKey), fmt.Sprintf("Data does not contain the container %s", refKey))
			}
			assert.Equal(t, len(resp.Data), len(reference), "Data does not contain the correct amount of containers")

			for dataKey, dataValue := range resp.Data {
				var data map[string]struct {
					Headers       map[string]map[string]string `mapstructure:"headers"`
					LatestVersion int                          `mapstructure:"latest_version"`
				}
				if err := mapstructure.Decode(dataValue, &data); err != nil {
					fmt.Println("failed decoding to mapstructure")

					return err
				}

				for _, refObj := range reference[dataKey] {
					assert.Assert(t, cmp.Contains(data, refObj), fmt.Sprintf("Container %s does not contain object %s", dataKey, refObj))
				}
				assert.Equal(t, len(data), len(reference[dataKey]), fmt.Sprintf("Container %s does not contain the correct amount of objects: %v", dataKey, data))

				for _, obj := range reference[dataKey] {
					var decryptedFile []byte
					version := data[obj].LatestVersion
					for {
						header := data[obj].Headers[strconv.Itoa(version)]["header"]
						decryptedFile, err = decryptFile(header, encryptedFiles[project+"/"+dataKey+"/"+obj], privateKey)
						if err == nil {
							break
						}
						version--
						if version == 0 {
							fmt.Println("Error decrypting file: ", err)

							return err
						}
					}
					var decryptedFileString = string(decryptedFile)
					assert.Equal(t, decryptedFileString, content, "Decrypted file and original content don't match")
				}
			}

			return nil
		},
	}
}

func testC4ghStepwiseReadBackupFile(t *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadBackupFile",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/backup/files/%s", project),
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			var data struct {
				Backup string `mapstructure:"backup"`
			}
			if err = mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}
			assert.Assert(t, cmp.Contains(resp.Data, "backup"), fmt.Sprintf("Response did not contain expected backup: %s", resp.Data))

			backupData, err := decodeJSON(data.Backup)
			if err != nil {
				return err
			}

			// we want to at least check the name of the contents
			var file struct {
				Name string `mapstructure:"name"`
			}
			if err = mapstructure.Decode(backupData, &file); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}

			assert.Equal(t, file.Name, project, fmt.Sprintf("Project name mismatch: %s", file))

			return nil
		},
	}
}

func testC4ghStepwiseWriteFileFail(_ *testing.T, project, container, path string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteFileFail",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		GetData: func() (map[string]any, error) {
			encryptedHeader, encryptedBody, err := encryptFile(oldKey, []byte(content))
			if err != nil {
				fmt.Println("Failed encrypting file: ", err)

				return nil, err
			}
			encryptedFiles[project+"/"+container+"/"+path] = encryptedBody

			return map[string]any{"header": base64.StdEncoding.EncodeToString(encryptedHeader)}, nil
		},
		Assert: func(_ *api.Secret, err error) error {
			if err == nil {
				return fmt.Errorf("Function should have failed")
			}

			return nil
		},
	}
}

func testC4ghStepwiseRotate(_ *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseRotate",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/keys/%s/rotate", project),
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseRewrap(_ *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseRewrap",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/rewrap/%s", project),
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

// encryptFile takes as input a receiver public key, and a file as an array of bytes.
// it returns the encrypted header, and encrypted body or error if it failed
func encryptFile(projectKey string, file []byte) ([]byte, []byte, error) {
	var keyBytes [chacha20poly1305.KeySize]byte
	decKey, _ := base64.StdEncoding.DecodeString(projectKey)
	copy(keyBytes[:], decKey)
	writeBuffer := new(bytes.Buffer)
	crypt4GHWriter, err := streaming.NewCrypt4GHWriterWithoutPrivateKey(writeBuffer, [][chacha20poly1305.KeySize]byte{keyBytes}, nil)
	if err != nil {
		fmt.Println("Failed to create crypt4GHWriter: ", err)

		return nil, nil, err
	}
	_, err = io.Copy(crypt4GHWriter, bytes.NewReader(file))
	if err != nil {
		fmt.Println("Failed to write c4gh: ", err)

		return nil, nil, err
	}
	err = crypt4GHWriter.Close()
	if err != nil {
		fmt.Println("Failed to close c4gh: ", err)

		return nil, nil, err
	}
	encryptedBody := writeBuffer.Bytes()
	encryptedHeader, err := headers.ReadHeader(bytes.NewReader(encryptedBody))
	if err != nil {
		fmt.Println("Failed reading header: ", err)

		return nil, nil, err
	}
	encryptedBody = encryptedBody[len(encryptedHeader):]

	return encryptedHeader, encryptedBody, nil
}

// decryptFile takes as input a base64 encoded header string, the encrypted body as bytes, and a private key.
// it returns the decrypted body or error if it failed
func decryptFile(header string, encryptedBody []byte, privateKey [chacha20poly1305.KeySize]byte) ([]byte, error) {
	decodedHeader, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		fmt.Println("Error decoding header: ", header, err)

		return nil, err
	}
	var file []byte
	file = append(file, decodedHeader...)
	file = append(file, encryptedBody...)
	crypt4GHReader, err := streaming.NewCrypt4GHReader(bytes.NewReader(file), privateKey, nil)
	if err != nil {
		fmt.Println("Error reading file: ", err)

		return nil, err
	}
	var decryptedBuffer = new(bytes.Buffer)
	_, err = io.Copy(decryptedBuffer, crypt4GHReader)
	if err != nil {
		fmt.Println("Error decrypting file: ", err)

		return nil, err
	}
	var decryptedFile = decryptedBuffer.Bytes()

	return decryptedFile, nil
}

func testC4ghStepwiseDeleteFile(_ *testing.T, project string, container string, path string, service string, keyName string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseDeleteFile",
		Operation: stepwise.DeleteOperation,
		Path:      fmt.Sprintf("files/%s/%s/%s", project, container, path),
		BodyData: map[string][]string{
			"service": {service},
			"key":     {keyName},
		},
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4hgStepwiseReadFileFail(_ *testing.T, project string, container string, path string, service string, keyName string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4hgStepwiseReadFileFail",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		BodyData: map[string][]string{
			"service": {service},
			"key":     {keyName},
		},
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}

			if resp != nil {
				return fmt.Errorf("response for data should be null")
			}

			return nil
		},
	}
}

func testC4ghStepwiseDeleteWhitelist(_ *testing.T, project string, service string, name string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseDeleteWhitelist",
		Operation: stepwise.DeleteOperation,
		Path:      fmt.Sprintf("whitelist/%s/%s/%s", project, service, name),
		Assert: func(_ *api.Secret, err error) error {
			return err
		},
	}
}

func testC4hgStepwiseReadWhitelistFileFail(_ *testing.T, project string, container string, path string, service string, keyName string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4hgStepwiseReadWhitelistFileFail",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		BodyData: map[string][]string{
			"service": {service},
			"key":     {keyName},
		},
		Assert: func(resp *api.Secret, err error) error {
			if err == nil {
				return fmt.Errorf("function should've failed")
			}
			if resp != nil {
				return fmt.Errorf("response for data should be null")
			}

			return nil
		},
	}
}
