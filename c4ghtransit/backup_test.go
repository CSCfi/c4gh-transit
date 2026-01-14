package c4ghtransit

import (
	"encoding/base64"
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
)

func TestLargerBackupAndRestore(t *testing.T) {
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
	containerPrefix := "bucket"
	pathPrefix := "file"
	limit := 100000

	steps := []stepwise.Step{}
	steps = append(steps, testC4ghStepwiseWriteKey(t, project))
	steps = append(steps, testC4ghStepwiseReadKey(t, project))
	steps = append(steps, testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString))
	for i := 1; i <= 100; i++ {
		for j := 1; j <= 100; j++ {
			container := containerPrefix + "-" + strconv.Itoa(i)
			path := pathPrefix + strconv.Itoa(j) + ".txt.c4gh"
			steps = append(steps, testC4ghStepwiseWriteFile(t, project, container, path))
		}
	}
	steps = append(steps, testC4ghStepwiseReadBackupFiles(t, project, limit))
	steps = append(steps, testC4ghStepwiseWriteRestoreFiles(t, project))
	for i := 1; i <= 10; i++ {
		for j := 1; j <= 100; j++ {
			container := containerPrefix + "-" + strconv.Itoa(i)
			path := pathPrefix + strconv.Itoa(j) + ".txt.c4gh"
			steps = append(steps, testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName))
		}
	}

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

func testC4ghStepwiseReadBackupFiles(t *testing.T, project string, _ int) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadBackupFiles",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/backup/files/%s", project),
		Assert: func(resp *api.Secret, err error) error {
			if err != nil {
				return err
			}
			if resp == nil {
				return fmt.Errorf("Response was nil")
			}
			assert.Assert(t, len(resp.Data) == 5, fmt.Sprintf("Response did not contain 5 backups, received %d", len(resp.Data)))

			var data struct {
				Backup1 string `mapstructure:"backup_1/5"`
				Backup2 string `mapstructure:"backup_2/5"`
				Backup3 string `mapstructure:"backup_3/5"`
				Backup4 string `mapstructure:"backup_4/5"`
				Backup5 string `mapstructure:"backup_5/5"`
			}
			if err = mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")

				return err
			}

			return nil
		},
	}
}

func testC4ghStepwiseWriteRestoreFiles(_ *testing.T, project string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadBackupFiles",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/restore/files/%s", project),
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
