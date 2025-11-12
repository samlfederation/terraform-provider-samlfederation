package provider

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	federationtypes "github.com/samlfederation/terraform-provider-samlfederation/internal/types"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig"
)

var _ datasource.DataSource = &MetadataDataSource{}

func NewMetadataDataSource() datasource.DataSource {
	return &MetadataDataSource{}
}

type MetadataDataSource struct {
}

func (i MetadataDataSource) Configure(_ context.Context, _ datasource.ConfigureRequest, _ *datasource.ConfigureResponse) {
}

func (i MetadataDataSource) Read(ctx context.Context, request datasource.ReadRequest, response *datasource.ReadResponse) {
	model := IdentityProvidersDataSourceModel{}
	response.Diagnostics.Append(request.Config.Get(ctx, &model)...)

	if response.Diagnostics.HasError() {
		return
	}

	xmlData := model.XML.ValueString()
	urlData := model.URL.ValueString()
	if xmlData != "" && urlData != "" {
		response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			xmlPath,
			"xml and url are mutually exclusive",
			"Please provide either the 'xml' or 'url' attribute, not both",
		))
	} else if xmlData == "" && urlData == "" {
		response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			xmlPath,
			"Either xml or url are required",
			"Please provide either the 'xml' or 'url' attribute",
		))
	}
	if response.Diagnostics.HasError() {
		return
	}
	sourcePath := xmlPath
	if urlData != "" {
		sourcePath = urlPath
		req, err := http.NewRequest(http.MethodGet, urlData, nil)
		if err != nil {
			response.Diagnostics.Append(
				diag.NewAttributeErrorDiagnostic(
					urlPath,
					"Invalid URL",
					err.Error(),
				),
			)
			return
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			response.Diagnostics.Append(
				diag.NewAttributeErrorDiagnostic(
					urlPath,
					fmt.Sprintf("Cannot fetch metadata XML from %s", urlData),
					err.Error(),
				),
			)
			return
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			response.Diagnostics.Append(
				diag.NewAttributeErrorDiagnostic(
					urlPath,
					fmt.Sprintf("Cannot read response body from %s", urlData),
					err.Error(),
				),
			)
			_ = resp.Body.Close()
			return
		}
		if resp.StatusCode != http.StatusOK {
			response.Diagnostics.Append(
				diag.NewAttributeErrorDiagnostic(
					urlPath,
					fmt.Sprintf("Invalid HTTP status code from %s (%d)", urlData, resp.StatusCode),
					string(body),
				),
			)
			_ = resp.Body.Close()
			return
		}
		if resp.Header.Get("Content-Type") != "application/xml" && resp.Header.Get("Content-Type") != "text/xml" && resp.Header.Get("Content-Type") != "application/samlmetadata+xml" {
			response.Diagnostics.Append(diag.NewWarningDiagnostic(
				"Non-XML data received",
				fmt.Sprintf("Server returned a Content-Type of %s, which is not XML. The metadata may not be XML and you may see parsing errors.", resp.Header.Get("Content-Type")),
			))
		}
		_ = resp.Body.Close()
		xmlData = string(body)
	}

	metadata := xmlData
	if !model.SigningCertificate.IsNull() && model.SigningCertificate.String() != "" {
		signingCertificate := model.SigningCertificate.ValueString()
		block, _ := pem.Decode([]byte(signingCertificate))
		if block == nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				signingCertificatePath,
				"cannot read signing certificate",
				"Non-PEM certificate data",
			))
			return
		}
		key, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				signingCertificatePath,
				"cannot read signing certificate",
				err.Error(),
			))
			return
		}
		validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
			Roots: []*x509.Certificate{key},
		})
		doc := etree.NewDocument()
		if err := doc.ReadFromString(metadata); err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				sourcePath,
				"cannot parse metadata",
				err.Error(),
			))
			return
		}
		validated, err := validationContext.Validate(doc.Root())
		if err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				sourcePath,
				"cannot validate metadata",
				err.Error(),
			))
			return
		}
		validatedDoc := etree.NewDocument()
		validatedDoc.SetRoot(validated)
		str, err := doc.WriteToString()
		if err != nil {
			response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
				sourcePath,
				"cannot marshal validated metadata",
				err.Error(),
			))
			return
		}
		metadata = str
	} else {
		response.Diagnostics.Append(diag.NewWarningDiagnostic(
			"No signing certificate provided",
			"No signing certificate was provided, the signature of the metadata file will not be verified.",
		))
	}

	federationData := federationtypes.FederationMetadata{}
	if err := xml.Unmarshal([]byte(metadata), &federationData); err != nil {
		response.Diagnostics.Append(diag.NewAttributeErrorDiagnostic(
			xmlPath,
			"cannot parse XML metadata",
			err.Error(),
		))
		return
	}
	identityProviders := map[string]IdentityProvider{}
	expectedAuthority := model.RegistrationAuthority.ValueString()

	for _, entityDescriptor := range federationData.EntityDescriptors {
		if len(entityDescriptor.IDPSSODescriptor.SingleSignOnServices) == 0 {
			continue
		}

		if entityDescriptor.EntityID == "" {
			continue
		}
		if expectedAuthority != "" && entityDescriptor.Extensions.RegistrationInfo.RegistrationAuthority != expectedAuthority {
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
		response.Diagnostics.Append(entry.applyDiscovery(ctx, entityDescriptor)...)
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
	obj, diags := basetypes.NewMapValueFrom(ctx, identityProviderType, identityProviders)
	response.Diagnostics.Append(diags...)
	response.Diagnostics.Append(response.State.SetAttribute(ctx, identityProvidersPath, obj)...)
}

func (i *MetadataDataSource) Metadata(_ context.Context, _ datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = "samlfederation_metadata"
}

func (i *MetadataDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Example data source",

		Attributes: map[string]schema.Attribute{
			xmlPath.String(): schema.StringAttribute{
				MarkdownDescription: "SAML federation metadata XML. You can feed the XML directly using this attribute, but be warned: the metadata is typically too large for the TF protocol (>256 MB). Use the URL option instead if you run into problems.",
				Optional:            true,
			},
			urlPath.String(): schema.StringAttribute{
				MarkdownDescription: "SAML federation metadata URL. The provider will fetch the metadata from this URL.",
				Optional:            true,
			},
			registrationAuthorityPath.String(): schema.StringAttribute{
				MarkdownDescription: "Only return identity providers by this registration authority.",
				Optional:            true,
			},
			signingCertificatePath.String(): schema.StringAttribute{
				MarkdownDescription: "PEM-encoded x509 certificate used for signing the metadata. If left empty, no verification will be performed and a warning will be issued.",
				Optional:            true,
			},
			identityProvidersPath.String(): schema.MapAttribute{
				ElementType:         identityProviderType,
				MarkdownDescription: "Map of identity providers keyed by their entityID.",
				Computed:            true,
			},
		},
	}
}
