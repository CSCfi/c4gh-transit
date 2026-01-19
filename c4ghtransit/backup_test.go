package c4ghtransit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"testing"

	stepwise "github.com/CSCfi/vault-testing-stepwise"
	"github.com/CSCfi/vault-testing-stepwise/environments/docker"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/neicnordic/crypt4gh/keys"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
)

var fileBackups []string
var whitelistBackup string
var whitelistBackupPrivateKey [32]byte
var eventualFileBackupCount = 5

func TestBackup(t *testing.T) {
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
	encryptedFiles = make(map[string][]byte)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])
	whitelistBackupPrivateKey = privateKey

	project := "my-project"
	service := "fake-service"
	keyName := "fake-key-name"
	containerPrefix := "bucket"
	pathPrefix := "file"
	limit := 100000 // a file with one header is bit less that 500 bytes -> one backup will include 2 containers

	steps := []stepwise.Step{}
	steps = append(steps, testC4ghStepwiseWriteKey(t, project))
	steps = append(steps, testC4ghStepwiseReadKey(t, project))
	steps = append(steps, testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString))
	steps = append(steps, testC4ghStepwiseReadWhitelist(t, project, service, keyName, publicKeyString))
	for i := 1; i <= 10; i++ {
		for j := 1; j <= 100; j++ {
			container := containerPrefix + "-" + strconv.Itoa(i)
			path := pathPrefix + strconv.Itoa(j) + ".txt.c4gh"
			steps = append(steps, testC4ghStepwiseWriteFile(t, project, container, path))
		}
	}
	steps = append(steps, testC4ghStepwiseReadBackupFiles(t, project, limit))
	steps = append(steps, testC4ghStepwiseReadBackupWhitelist(t, project))
	steps = append(steps, testC4ghStepwiseReadBackupKey(t, project))

	// Running the case compiles the plugin with Docker, and runs Vault with the plugin enabled.
	// Each step in a case is run sequentially.
	// At the end of the case, the Docker container and network are removed, unless `SkipTeardown` is set to `true`
	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps:        steps,
	}
	stepwise.Run(t, simpleCase)
}

func TestRestore(t *testing.T) {
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

	project := "my-project"
	projectCopy := "my-project-copy"
	service := "fake-service"
	keyName := "fake-key-name"
	containerPrefix := "bucket"
	pathPrefix := "file"

	steps := []stepwise.Step{}
	for i := range eventualFileBackupCount {
		steps = append(steps, testC4ghStepwiseWriteRestore(t, "files", projectCopy, fileBackups[i]))
	}
	steps = append(steps, testC4ghStepwiseWriteRestore(t, "whitelist", projectCopy, whitelistBackup))
	for i := 1; i <= 10; i++ {
		for j := 1; j <= 100; j++ {
			container := containerPrefix + "-" + strconv.Itoa(i)
			path := pathPrefix + strconv.Itoa(j) + ".txt.c4gh"
			encryptedFiles[projectCopy+"/"+container+"/"+path] = encryptedFiles[project+"/"+container+"/"+path]
			delete(encryptedFiles, project+"/"+container+"/"+path)
			steps = append(steps, testC4ghStepwiseReadFile(t, projectCopy, container, path, whitelistBackupPrivateKey, service, keyName))
		}
	}

	simpleCase := stepwise.Case{
		Environment:  env,
		SkipTeardown: false,
		Steps:        steps,
	}
	stepwise.Run(t, simpleCase)
}

func TestBackupList(t *testing.T) {
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
	encryptedFiles = make(map[string][]byte)

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
			// List backup keys
			testC4ghStepwiseListBackup(t, "keys", project),
			// List backup files
			testC4ghStepwiseListBackup(t, "files", project),
		},
	}
	stepwise.Run(t, simpleCase)
}

func testC4ghStepwiseReadBackupFiles(t *testing.T, project string, limit int) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadBackupFiles",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/backup/files/%s", project),
		BodyData: map[string][]string{
			"limit": {strconv.Itoa(limit)},
		},
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			var data struct {
				Backup []string `mapstructure:"backup"`
			}
			if err = mapstructure.Decode(resp.Data, &data); err != nil {
				return fmt.Errorf("failed decoding response to mapstructure: %w", err)
			}

			assert.Assert(t, len(data.Backup) == eventualFileBackupCount, fmt.Sprintf("Response did not contain %d backups, received %d", eventualFileBackupCount, len(data.Backup)))
			for i := range data.Backup {
				assert.Assert(t, len(data.Backup[i]) <= limit, fmt.Sprintf("Backup no. %d was too long (%d bytes)", limit, len(data.Backup[i])))

				var files struct {
					Name string `json:"name"`
				}
				bytes, err := base64.StdEncoding.DecodeString(data.Backup[i])
				if err != nil {
					return fmt.Errorf("failed decoding backup no. %d from base64: %w", i+1, err)
				}
				if err = json.Unmarshal(bytes, &files); err != nil {
					return fmt.Errorf("failed unmarshal backup no. %d: %w", i+1, err)
				}
				assert.Equal(t, files.Name, project, fmt.Sprintf("Project name mismatch: %s", files.Name))
			}

			fileBackups = data.Backup

			return nil
		},
	}
}

func testC4ghStepwiseReadBackupWhitelist(t *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadBackupWhitelist",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/backup/whitelist/%s", project),
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
				return fmt.Errorf("failed decoding response to mapstructure: %w", err)
			}

			var files struct {
				Name string `json:"name"`
			}
			bytes, err := base64.StdEncoding.DecodeString(data.Backup)
			if err != nil {
				return fmt.Errorf("failed decoding whitelist backup from base64: %w", err)
			}
			if err = json.Unmarshal(bytes, &files); err != nil {
				return fmt.Errorf("failed unmarshal whitelist backup: %w", err)
			}
			assert.Equal(t, files.Name, project, fmt.Sprintf("Project name mismatch: %s", files.Name))

			whitelistBackup = data.Backup

			return nil
		},
	}
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
				return fmt.Errorf("failed decoding response to mapstructure: %w", err)
			}

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

func decodeJSON(encodedString string) (map[string]any, error) {
	bytes, err := base64.StdEncoding.DecodeString(encodedString) // Converting data
	if err != nil {
		return nil, fmt.Errorf("failed to decode from base64: %w", err)
	}

	var decodedJSON map[string]any
	if err = json.Unmarshal(bytes, &decodedJSON); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return decodedJSON, nil
}

func testC4ghStepwiseWriteRestore(_ *testing.T, backupType string, project string, backup string) stepwise.Step {
	return stepwise.Step{
		Name:      fmt.Sprintf("testC4ghStepwiseWriteRestoreFiles-%s", backupType),
		Operation: stepwise.UpdateOperation,
		Path:      fmt.Sprintf("/restore/%s/%s", backupType, project),
		Data:      map[string]any{"backup": backup},
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}

			return nil
		},
	}
}

func testC4ghStepwiseListBackup(t *testing.T, backupType string, project string) stepwise.Step {
	return stepwise.Step{
		Name:      fmt.Sprintf("testC4ghStepwiseListBackup-%s", backupType),
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
				return fmt.Errorf("failed decoding response to mapstructure: %w", err)
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
