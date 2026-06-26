package c4ghtransit

import (
	"encoding/base64"
	"strconv"
	"testing"

	stepwise "github.com/CSCfi/vault-testing-stepwise"
	"github.com/neicnordic/crypt4gh/keys"
)

func TestKeyRotateMultipleTimes(t *testing.T) {
	env := setup(t)
	encryptedFiles = make(map[string][]byte)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate crypt4gh key pair %v", err)
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
	env := setup(t)
	encryptedFiles = make(map[string][]byte)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate crypt4gh key pair %v", err)
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
