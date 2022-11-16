package main

import (
	"flag"
	"os"

	"github.com/cscfi/c4gh-transit/c4ghtransit/c4ghtransit"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			// returning help
			os.Exit(0)
		}
		os.Exit(1)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	println("Starting to serve the c4ghtransit plugin.\n")

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: c4ghtransit.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logger := hclog.New(&hclog.LoggerOptions{})

		logger.Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
