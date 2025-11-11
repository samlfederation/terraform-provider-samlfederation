package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/samlfederation/terraform-provider-samlfederation/internal/provider"
)

var version string = "dev"

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "Enable debugging with DLV.")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.opentofu.org/samlfederation/samlfederation",
		Debug:   debug,
	}

	err := providerserver.Serve(context.Background(), provider.New(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
