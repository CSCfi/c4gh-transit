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
	"github.com/neicnordic/crypt4gh/keys"
)

func TestKeyRotateMultipleTimes(t *testing.T) {
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
	pathPrefix := "file"
	fileCount := 1000

	steps := []stepwise.Step{}
	steps = append(steps, testC4ghStepwiseWriteKey(t, project))
	steps = append(steps, testC4ghStepwiseReadKey(t, project))
	steps = append(steps, testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString))
	for i := 1; i <= fileCount; i++ {
		path := pathPrefix + strconv.Itoa(i) + ".txt.c4gh"
		steps = append(steps, testC4ghStepwiseWriteFile(t, project, container, path))
		steps = append(steps, testC4ghStepwiseRotate(t, project))
		steps = append(steps, testC4ghStepwiseReadKey(t, project))
	}
	for i := 1; i <= fileCount; i++ {
		path := pathPrefix + strconv.Itoa(i) + ".txt.c4gh"
		steps = append(steps, testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName))
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

func TestKeyRotateMultipleTimesAndRewrap(t *testing.T) {
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
	pathPrefix := "file"
	fileCount := 1000

	steps := []stepwise.Step{}
	steps = append(steps, testC4ghStepwiseWriteKey(t, project))
	steps = append(steps, testC4ghStepwiseReadKey(t, project))
	steps = append(steps, testC4ghStepwiseWriteWhitelist(t, project, service, keyName, publicKeyString))
	for i := 1; i <= fileCount; i++ {
		path := pathPrefix + strconv.Itoa(i) + ".txt.c4gh"
		steps = append(steps, testC4ghStepwiseWriteFile(t, project, container, path))
	}
	steps = append(steps, testC4ghStepwiseRotate(t, project))
	steps = append(steps, testC4ghStepwiseReadKey(t, project))
	steps = append(steps, testC4ghStepwiseWriteFileFail(t, project, container,
		pathPrefix+strconv.Itoa(fileCount+1)+".txt.c4gh"))
	for i := 1; i <= fileCount; i++ {
		path := pathPrefix + strconv.Itoa(i) + ".txt.c4gh"
		steps = append(steps, testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName))
	}
	steps = append(steps, testC4ghStepwiseRewrap(t, project))
	for i := 1; i <= fileCount; i++ {
		path := pathPrefix + strconv.Itoa(i) + ".txt.c4gh"
		steps = append(steps, testC4ghStepwiseReadFile(t, project, container, path, privateKey, service, keyName))
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
