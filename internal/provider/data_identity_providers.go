package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	federationtypes "github.com/samlfederation/terraform-provider-samlfederation/internal/types"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
)

var _ datasource.DataSource = &IdentityProvidersDataSource{}

func NewIdentityProvidersDataSource() datasource.DataSource {
	return &IdentityProvidersDataSource{}
}

type IdentityProvidersDataSource struct {
}

func (i IdentityProvidersDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
}

func (i IdentityProvidersDataSource) Read(ctx context.Context, request datasource.ReadRequest, response *datasource.ReadResponse) {
	model := IdentityProvidersDataSourceModel{}
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)

	if response.Diagnostics.HasError() {
		return
	}
	metadata := model.Metadata.String()
	if !model.SigningCertificate.IsNull() && model.SigningCertificate.String() != "" {
		block, _ := pem.Decode([]byte(model.SigningCertificate.String()))
		key, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				path.Root("signing_certificate"),
				"cannot read signing certificate",
				err.Error(),
			))
			return
		}
		ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{key},
		})
		doc := etree.NewDocument()
		if err := doc.ReadFromString(metadata); err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				path.Root("metadata"),
				"cannot parse metadata",
				err.Error(),
			))
			return
		}
		validated, err := ctx.Validate(doc.Root())
		if err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				path.Root("metadata"),
				"cannot validate metadata",
				err.Error(),
			))
			return
		}
		validatedXMLData, err := xml.Marshal(validated)
		if err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				path.Root("metadata"),
				"cannot marshal validated metadata",
				err.Error(),
			))
			return
		}
		metadata = string(validatedXMLData)
	} else {
		response.Diagnostics.Append(diag.NewWarningDiagnostic("No signing certificate provided", "No signing certificate was provided, the signature of the metadata file will not be verified."))
	}

	federationData := federationtypes.FederationMetadata{}
	if err := xml.Unmarshal([]byte(metadata), &federationData); err != nil {
		response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			path.Root("metadata"),
			"cannot parse XML metadata",
			err.Error(),
		))
		return
	}
	identityProviders := map[string]IdentityProvider{}

	for _, entityDescriptor := range federationData.EntityDescriptors {
		if len(entityDescriptor.IDPSSODescriptor.SingleSignOnServices) == 0 {
			continue
		}

		if entityDescriptor.EntityID == "" {
			continue
		}
		entry := IdentityProvider{
			DisplayNames:         types.List{},
			Descriptions:         types.List{},
			InformationURLs:      types.List{},
			PrivacyStatementURL:  types.List{},
			Logos:                types.List{},
			RegistrationInfo:     types.Object{},
			Keywords:             types.List{},
			X509Certificates:     types.List{},
			SingleSignOnServices: types.List{},
			SingleLogoutServices: types.List{},
		}
		response.Diagnostics.Append(entry.applyDisplayNames(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyDescriptions(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyInformationURLs(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyPrivacyStatementURLs(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyLogos(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyRegistrationInfo(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyKeywords(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applyX509Certificates(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applySingleSignOnServices(ctx, entityDescriptor)...)
		response.Diagnostics.Append(entry.applySingleLogoutServices(ctx, entityDescriptor)...)

		if response.Diagnostics.HasError() {
			return
		}
		if len(entry.SingleSignOnServices.Elements()) == 0 {
			// This is a Service Provider, not an Identity Provider.
			continue
		}

		identityProviders[entityDescriptor.EntityID] = entry
	}
}

type IdentityProvidersDataSourceModel struct {
	Metadata           types.String `tfsdk:"metadata"`
	SigningCertificate types.String `tfsdk:"signing_certificate"`
	IdentityProviders  types.Map    `tfsdk:"identity_providers"`
}

type IdentityProvider struct {
	DisplayNames         types.List   `tfsdk:"display_names"`
	Descriptions         types.List   `tfsdk:"descriptions"`
	InformationURLs      types.List   `tfsdk:"information_urls"`
	PrivacyStatementURL  types.List   `tfsdk:"privacy_statement_url"`
	Logos                types.List   `tfsdk:"logos"`
	RegistrationInfo     types.Object `tfsdk:"registration_info"`
	Keywords             types.List   `tfsdk:"keywords"`
	X509Certificates     types.List   `tfsdk:"x509_certificates"`
	SingleSignOnServices types.List   `tfsdk:"single_sign_on_services"`
	SingleLogoutServices types.List   `tfsdk:"single_logout_services"`
}

func (i *IdentityProvider) processLocalizedString(ctx context.Context, source []federationtypes.FederationUIString) (types.List, diag.Diagnostics) {
	var destination []LocalizedString
	for _, displayNameElement := range source {
		destination = append(destination, LocalizedString{
			Language: basetypes.NewStringValue(displayNameElement.Lang),
			Text:     basetypes.NewStringValue(displayNameElement.Value),
		})
	}
	return basetypes.NewListValueFrom(ctx, localizedStringType, destination)
}

func (i *IdentityProvider) applyDisplayNames(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.DisplayNames, diags = i.processLocalizedString(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.DisplayNames)
	return diags
}

func (i *IdentityProvider) applyDescriptions(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.Descriptions, diags = i.processLocalizedString(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.Descriptions)
	return diags
}

func (i *IdentityProvider) applyInformationURLs(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.InformationURLs, diags = i.processLocalizedString(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.InformationURLs)
	return diags
}

func (i *IdentityProvider) applyPrivacyStatementURLs(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.PrivacyStatementURL, diags = i.processLocalizedString(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.PrivacyStatementURLs)
	return diags
}

func (i *IdentityProvider) applyKeywords(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.Keywords, diags = i.processLocalizedString(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.Keywords)
	return diags
}

func (i *IdentityProvider) applyLogos(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {

}

func (i *IdentityProvider) applyRegistrationInfo(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {

}

func (i *IdentityProvider) applyX509Certificates(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {

}

func (i *IdentityProvider) applySingleSignOnServices(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {

}

func (i *IdentityProvider) applySingleLogoutServices(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {

}

var localizedStringType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"language": types.StringType,
		"text":     types.StringType,
	},
}

type LocalizedString struct {
	Language types.String `tfsdk:"language"`
	Text     types.String `tfsdk:"text"`
}

type LocalizedURL struct {
	Language types.String `tfsdk:"language"`
	URL      types.String `tfsdk:"url"`
}

type Logo struct {
	Height types.Int64  `tfsdk:"height"`
	Width  types.Int64  `tfsdk:"width"`
	URL    types.String `tfsdk:"url"`
}

type X509Certificate struct {
	Signing    types.Bool   `tfsdk:"signing"`
	Encryption types.Bool   `tfsdk:"encryption"`
	PEM        types.String `tfsdk:"pem"`
}

type Discovery struct {
	Domains      types.List `tfsdk:"domains"`
	IPRanges     types.List `tfsdk:"ip_ranges"`
	GeoLocations types.List `tfsdk:"geo_locations"`
}

type IPRange struct {
	BaseIP types.String `tfsdk:"base_ip"`
	Mask   types.Int32  `tfsdk:"mask"`
}

type Geo struct {
	Longitude types.Float64 `tfsdk:"longitude"`
	Latitude  types.Float64 `tfsdk:"latitude"`
}

type RegistrationInfo struct {
	Authority types.String `tfsdk:"authority"`
}

type Service struct {
	Binding  types.String `tfsdk:"binding"`
	Location types.String `tfsdk:"location"`
}

func (i *IdentityProvidersDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_identity_providers"
}

func (i *IdentityProvidersDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Example data source",

		Attributes: map[string]schema.Attribute{
			"metadata": schema.StringAttribute{
				MarkdownDescription: "SAML federation metadata XML",
				Required:            true,
			},
			"signing_certificate": schema.StringAttribute{
				MarkdownDescription: "PEM-encoded x509 certificate used for signing the metadata. If left empty, no verification will be performed and a warning will be issued.",
				Optional:            true,
			},
			"identity_providers": schema.ObjectAttribute{
				AttributeTypes: map[string]attr.Type{
					"display_names": types.ListType{
						ElemType: localizedStringType,
					},
					"descriptions": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"language": types.StringType,
								"text":     types.StringType,
							},
						},
					},
					"information_urls": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"language": types.StringType,
								"url":      types.StringType,
							},
						},
					},
					"privacy_statement_url": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"language": types.StringType,
								"url":      types.StringType,
							},
						},
					},
					"logos": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"width":  types.Int64Type,
								"height": types.Int64Type,
								"url":    types.StringType,
							},
						},
					},
					"registration_info": types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"authority": types.StringType,
						},
					},
					"keywords": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"language": types.StringType,
								"text":     types.StringType,
							},
						},
					},
					"x509_certificates": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"encryption": types.BoolType,
								"signing":    types.BoolType,
								"pem":        types.StringType,
							},
						},
					},
					"discovery": types.ObjectType{
						AttrTypes: map[string]attr.Type{
							"ip_ranges": types.ListType{
								ElemType: types.ObjectType{
									AttrTypes: map[string]attr.Type{
										"base_ip": types.StringType,
										"mask":    types.Int32Type,
									},
								},
							},
							"domains": types.ListType{
								ElemType: types.StringType,
							},
							"geo_locations": types.ListType{
								ElemType: types.ObjectType{
									AttrTypes: map[string]attr.Type{
										"longitude": types.Float64Type,
										"latitude":  types.Float64Type,
									},
								},
							},
						},
					},
					"single_sign_on_services": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"binding":  types.StringType,
								"location": types.StringType,
							},
						},
					},
					"single_logout_services": types.ListType{
						ElemType: types.ObjectType{
							AttrTypes: map[string]attr.Type{
								"binding":  types.StringType,
								"location": types.StringType,
							},
						},
					},
				},
				MarkdownDescription: "Map of identity providers keyed by their entityID.",
				Computed:            true,
			},
		},
	}
}
