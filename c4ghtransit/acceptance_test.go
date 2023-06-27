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
			// TODO: Tests for deletion sync, stepwise client doesn't seem to support usage with params in deletion.
			// Remove access to decryption
			// testC4ghStepwiseDeleteSharingWhitelist(t, project, container, otherProject),
			// Check the download fails again
			// testC4hgStepwiseReadShareFileFail(t, otherProject, container, path, service, keyName, project),
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
		},
	}
	stepwise.Run(t, simpleCase)
}

func testC4ghStepwiseWriteKey(_ *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteKey",
		Operation: stepwise.WriteOperation,
		Data:      map[string]interface{}{"flavor": "crypt4gh"},
		Path:      fmt.Sprintf("/keys/%s", project),
		Assert: func(resp *api.Secret, err error) error {
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

func decodeJSON(encodedString string) (map[string]interface{}, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedString) // Converting data

	if err != nil {
		fmt.Println("Failed to Decode from base64", err)

		return nil, err
	}

	var decodedJSON map[string]interface{}
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
				Keys []interface{} `mapstructure:"keys"`
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
		Data:      map[string]interface{}{"flavor": "crypt4gh", "pubkey": publicKey},
		Path:      fmt.Sprintf("/whitelist/%s/%s/%s", project, service, keyName),
		Assert: func(resp *api.Secret, err error) error {
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
		GetData: func() (map[string]interface{}, error) {
			return map[string]interface{}{
				"id":         otherProject,
				"idkeystone": otherProjectID,
			}, nil
		},
		Assert: func(resp *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseReadSharingWhitelist(t *testing.T, project string, container string, otherProject string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadSharingWhitelist",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		ReadData: map[string][]string{
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

// Leave this for later, from the look of it stepwise doesn't support parameters in delete requests yet.
// nolint:unused
func testC4ghStepwiseDeleteSharingWhitelist(_ *testing.T, project string, container string, otherProject string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseDeleteSharingWhitelist",
		Operation: stepwise.DeleteOperation,
		Path:      fmt.Sprintf("/sharing/%s/%s", project, container),
		ReadData: map[string][]string{
			"id": {otherProject},
		},
		Assert: func(resp *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseWriteFile(_ *testing.T, project, container, path string, otherContent ...string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteFile",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		GetData: func() (map[string]interface{}, error) {
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
				encryptedFiles[path] = encryptedBody
			}

			return map[string]interface{}{"header": base64.StdEncoding.EncodeToString(encryptedHeader)}, nil
		},
		Assert: func(resp *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseWriteSharedFile(_ *testing.T, project, container, path string, owner string, otherContent ...string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteSharedFile",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		GetData: func() (map[string]interface{}, error) {
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
				encryptedFiles[path] = encryptedBody
			}

			return map[string]interface{}{
				"header": base64.StdEncoding.EncodeToString(encryptedHeader),
				"owner":  owner,
			}, nil
		},
		Assert: func(resp *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseReadFile(t *testing.T, project string, container string, path string, privateKey [chacha20poly1305.KeySize]byte, service string, keyName string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadFile",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		ReadData: map[string][]string{
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
				decryptedFile, err = decryptFile(header, encryptedFiles[path], privateKey)
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
		ReadData: map[string][]string{
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
				decryptedFile, err = decryptFile(header, encryptedFiles[path], privateKey)
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
		ReadData: map[string][]string{
			"service": {service},
			"key":     {keyName},
			"owner":   {owner},
		},
		Assert: func(resp *api.Secret, err error) error {
			if err == nil {
				return fmt.Errorf("function should've failed")
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
		GetData: func() (map[string]interface{}, error) {
			encryptedHeader, encryptedBody, err := encryptFile(oldKey, []byte(content))
			if err != nil {
				fmt.Println("Failed encrypting file: ", err)

				return nil, err
			}
			encryptedFiles[path] = encryptedBody

			return map[string]interface{}{"header": base64.StdEncoding.EncodeToString(encryptedHeader)}, nil
		},
		Assert: func(resp *api.Secret, err error) error {
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
		Assert: func(resp *api.Secret, err error) error {
			return err
		},
	}
}

func testC4ghStepwiseRewrap(_ *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseRewrap",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/rewrap/%s", project),
		Assert: func(resp *api.Secret, err error) error {
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
