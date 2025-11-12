package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var _ provider.Provider = &SAMLFederationProvider{}
var _ provider.ProviderWithFunctions = &SAMLFederationProvider{}
var _ provider.ProviderWithEphemeralResources = &SAMLFederationProvider{}

// New initializes a new SAMLFederationProvider with the given version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &SAMLFederationProvider{
			version: version,
		}
	}
}

// SAMLFederationProvider implements the TF Provider for reading SAML federation metadata files.
type SAMLFederationProvider struct {
	version string
}

type ScaffoldingProviderModel struct {
}

func (p *SAMLFederationProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "samlfederation"
	resp.Version = p.version
}

func (p *SAMLFederationProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}

func (p *SAMLFederationProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *SAMLFederationProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *SAMLFederationProvider) EphemeralResources(_ context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *SAMLFederationProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewMetadataDataSource,
	}
}

func (p *SAMLFederationProvider) Functions(_ context.Context) []func() function.Function {
	return []func() function.Function{}
}
