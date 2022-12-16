package c4ghtransit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/CSCfi/vault-testing-stepwise/environments/docker"
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/neicnordic/crypt4gh/keys"
	"github.com/neicnordic/crypt4gh/model/headers"
	"github.com/neicnordic/crypt4gh/streaming"
	"golang.org/x/crypto/chacha20poly1305"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"io"
	"os"
	"testing"

	stepwise "github.com/CSCfi/vault-testing-stepwise"
)

var (
	projectKey    string
	encryptedFile []byte
	content       = "Hide your secrets in a bucket."
)

func TestKeys(t *testing.T) {
	err := os.Setenv("VAULT_ACC", "1")
	if err != nil {
		t.Error("Failed to set VAULT_ACC")
	}
	mountOptions := stepwise.MountOptions{
		MountPathPrefix: "c4ghtransit",
		RegistryName:    "c4ghtransit",
		PluginType:      stepwise.PluginTypeSecrets,
		PluginName:      "c4ghtransit",
	}
	env := docker.NewEnvironment("DockerKeys", &mountOptions)

	publicKey, privateKey, err := keys.GenerateKeyPair()
	if err != nil {
		fmt.Print("Failed to generate crypt4gh key pair")
		t.Error(err)
	}
	publicKeyString := base64.StdEncoding.EncodeToString(publicKey[:])

	project := "my-project"
	service := "fake-service"
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
			testC4ghStepwiseWriteWhitelist(t, project, service, publicKeyString),
			// Confirm key exists
			testC4ghStepwiseReadWhitelist(t, project, service, publicKeyString),
			// Upload encrypt file
			testC4ghStepwiseWriteFile(t, project, container, path),
			// Download encrypted file, and confirm it can be decrypted
			testC4ghStepwiseReadFile(t, project, container, path, privateKey),
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

			projectKey = data.Keys[fmt.Sprintf("%d", data.LatestVersion)]["public_key_c4gh_64"]

			return nil
		},
	}
}

func testC4ghStepwiseWriteWhitelist(_ *testing.T, project string, service string, publicKey string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteWhitelist",
		Operation: stepwise.WriteOperation,
		Data:      map[string]interface{}{"flavor": "crypt4gh", "pubkey": publicKey},
		Path:      fmt.Sprintf("/whitelist/%s/%s", project, service),
	}
}

func testC4ghStepwiseReadWhitelist(t *testing.T, project string, service string, publicKey string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadWhitelist",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/whitelist/%s/%s", project, service),
		Assert: func(resp *api.Secret, err error) error {
			assert.Equal(t, resp.Data["key"], publicKey, fmt.Sprintf("Response did not contain expected key: %s", resp.Data))
			assert.Equal(t, resp.Data["project"], project, fmt.Sprintf("Response did not contain expected project: %s", resp.Data))
			assert.Equal(t, resp.Data["service"], service, fmt.Sprintf("Response did not contain expected service: %s", resp.Data))
			if err != nil {
				return err
			}
			return nil
		},
	}
}

func testC4ghStepwiseWriteFile(_ *testing.T, project string, container string, path string) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseWriteFile",
		Operation: stepwise.WriteOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		GetData: func() (map[string]interface{}, error) {
			var keyBytes [chacha20poly1305.KeySize]byte
			decKey, _ := base64.StdEncoding.DecodeString(projectKey)
			copy(keyBytes[:], decKey)
			writeBuffer := new(bytes.Buffer)
			crypt4GHWriter, err := streaming.NewCrypt4GHWriterWithoutPrivateKey(writeBuffer, [][chacha20poly1305.KeySize]byte{keyBytes}, nil)
			if err != nil {
				fmt.Println("Failed to create crypt4GHWriter: ", err)

				return nil, err
			}
			_, err = io.Copy(crypt4GHWriter, bytes.NewReader([]byte(content)))
			if err != nil {
				fmt.Println("Failed to write c4gh: ", err)

				return nil, err
			}
			err = crypt4GHWriter.Close()
			if err != nil {
				fmt.Println("Failed to close c4gh: ", err)

				return nil, err

			}
			encryptedFile = writeBuffer.Bytes()
			encryptedHeader, err := headers.ReadHeader(bytes.NewReader(encryptedFile))
			if err != nil {
				fmt.Println("Failed reading header: ", err)

				return nil, err
			}
			encryptedFile = encryptedFile[len(encryptedHeader):]

			return map[string]interface{}{"header": base64.StdEncoding.EncodeToString(encryptedHeader)}, nil
		},
	}
}

func testC4ghStepwiseReadFile(t *testing.T, project string, container string, path string, privateKey [chacha20poly1305.KeySize]byte) stepwise.Step {
	return stepwise.Step{
		Name:      "testC4ghStepwiseReadFile",
		Operation: stepwise.ReadOperation,
		Path:      fmt.Sprintf("/files/%s/%s/%s", project, container, path),
		Assert: func(resp *api.Secret, err error) error {

			var data struct {
				Header     string `mapstructure:"header"`
				KeyVersion int    `mapstructure:"keyversion"`
			}
			if err := mapstructure.Decode(resp.Data, &data); err != nil {
				fmt.Println("failed decoding to mapstructure")
				return err
			}
			decodedHeader, err := base64.StdEncoding.DecodeString(data.Header)
			if err != nil {
				fmt.Println("Error decoding header: ", data.Header, err)

				return err
			}
			file := append(decodedHeader, encryptedFile...)
			crypt4GHReader, err := streaming.NewCrypt4GHReader(bytes.NewReader(file), privateKey, nil)
			if err != nil {
				fmt.Println("Error reading file: ", err)

				return err
			}
			var decryptedBuffer = new(bytes.Buffer)
			_, err = io.Copy(decryptedBuffer, crypt4GHReader)
			if err != nil {
				fmt.Println("Error decrypting file: ", err)

				return err
			}
			var decryptedFile = decryptedBuffer.Bytes()
			var decryptedFileString = string(decryptedFile)

			assert.Equal(t, decryptedFileString, content, "Decrypted file and original content don't match")

			return err
		},
	}
}
