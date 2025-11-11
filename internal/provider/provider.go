package provider

import (
	"context"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

func (p *SAMLFederationProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "samlfederation"
	resp.Version = p.version
}

func (p *SAMLFederationProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{},
	}
}

func (p *SAMLFederationProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

func (p *SAMLFederationProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *SAMLFederationProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{}
}

func (p *SAMLFederationProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewIdentityProvidersDataSource,
	}
}

func (p *SAMLFederationProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}
