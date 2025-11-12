package provider

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	federationtypes "github.com/samlfederation/terraform-provider-samlfederation/internal/types"
)

type LocalizedString struct {
	Language types.String `tfsdk:"language"`
	Text     types.String `tfsdk:"text"`
}

var localizedStringType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"language": types.StringType,
		"text":     types.StringType,
	},
}

type LocalizedURL struct {
	Language types.String `tfsdk:"language"`
	URL      types.String `tfsdk:"url"`
}

var localizedURLType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"language": types.StringType,
		"url":      types.StringType,
	},
}

type Logo struct {
	Height types.Int64  `tfsdk:"height"`
	Width  types.Int64  `tfsdk:"width"`
	URL    types.String `tfsdk:"url"`
}

var logoType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"width":  types.Int64Type,
		"height": types.Int64Type,
		"url":    types.StringType,
	},
}

type RegistrationInfo struct {
	Authority types.String `tfsdk:"authority"`
}

var registrationInfoType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"authority": types.StringType,
	},
}

type X509Certificate struct {
	Signing    types.Bool   `tfsdk:"signing"`
	Encryption types.Bool   `tfsdk:"encryption"`
	PEM        types.String `tfsdk:"pem"`
}

var x509CertificateType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"encryption": types.BoolType,
		"signing":    types.BoolType,
		"pem":        types.StringType,
	},
}

type Discovery struct {
	Domains      types.List `tfsdk:"domains"`
	IPRanges     types.List `tfsdk:"ip_ranges"`
	GeoLocations types.List `tfsdk:"geo_locations"`
}

var discoveryType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"ip_ranges":     types.ListType{ElemType: ipRangeType},
		"domains":       types.ListType{ElemType: types.StringType},
		"geo_locations": types.ListType{ElemType: geoLocationType},
	},
}

type IPRange struct {
	BaseIP types.String `tfsdk:"base_ip"`
	Mask   types.Int32  `tfsdk:"mask"`
}

var ipRangeType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"base_ip": types.StringType,
		"mask":    types.Int32Type,
	},
}

type GeoLocation struct {
	Latitude  types.Float64 `tfsdk:"latitude"`
	Longitude types.Float64 `tfsdk:"longitude"`
}

var geoLocationType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"longitude": types.Float64Type,
		"latitude":  types.Float64Type,
	},
}

type Service struct {
	Binding  types.String `tfsdk:"binding"`
	Location types.String `tfsdk:"location"`
}

var serviceType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"binding":  types.StringType,
		"location": types.StringType,
	},
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
	Discovery            types.Object `tfsdk:"discovery"`
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
	if destination == nil {
		destination = []LocalizedString{}
	}
	return basetypes.NewListValueFrom(ctx, localizedStringType, destination)
}

func (i *IdentityProvider) processLocalizedURL(ctx context.Context, source []federationtypes.FederationUIString) (types.List, diag.Diagnostics) {
	var destination []LocalizedURL
	for _, displayNameElement := range source {
		destination = append(destination, LocalizedURL{
			Language: basetypes.NewStringValue(displayNameElement.Lang),
			URL:      basetypes.NewStringValue(displayNameElement.Value),
		})
	}
	if destination == nil {
		destination = []LocalizedURL{}
	}
	return basetypes.NewListValueFrom(ctx, localizedURLType, destination)
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
	i.InformationURLs, diags = i.processLocalizedURL(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.InformationURLs)
	return diags
}

func (i *IdentityProvider) applyPrivacyStatementURLs(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.PrivacyStatementURL, diags = i.processLocalizedURL(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.PrivacyStatementURLs)
	return diags
}

func (i *IdentityProvider) applyKeywords(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.Keywords, diags = i.processLocalizedString(ctx, entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.Keywords)
	return diags
}

func (i *IdentityProvider) applyLogos(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	var results []Logo
	for _, logoData := range entityDescriptor.IDPSSODescriptor.Extensions.UIInfo.Logos {
		results = append(results, Logo{
			Height: basetypes.NewInt64Value(int64(logoData.Height)),
			Width:  basetypes.NewInt64Value(int64(logoData.Width)),
			URL:    basetypes.NewStringValue(logoData.URL),
		})
	}
	if results == nil {
		results = []Logo{}
	}
	i.Logos, diags = basetypes.NewListValueFrom(ctx, logoType, results)
	return diags
}

func (i *IdentityProvider) applyRegistrationInfo(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.RegistrationInfo, diags = basetypes.NewObjectValueFrom(ctx, registrationInfoType.AttrTypes, RegistrationInfo{
		Authority: basetypes.NewStringValue(entityDescriptor.Extensions.RegistrationInfo.RegistrationAuthority),
	})
	return diags
}

func (i *IdentityProvider) applyX509Certificates(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	var certs []attr.Value
	for _, keyDescriptor := range entityDescriptor.IDPSSODescriptor.KeyDescriptors {
		if keyDescriptor.KeyInfo.X509Data.X509Certificate == "" {
			// This is not an x509 key, ignore
			continue
		}
		cert, d := basetypes.NewObjectValueFrom(ctx, x509CertificateType.AttrTypes, X509Certificate{
			Signing:    basetypes.NewBoolValue(keyDescriptor.Use == "signing"),
			Encryption: basetypes.NewBoolValue(keyDescriptor.Use == "encryption"),
			PEM:        basetypes.NewStringValue(keyDescriptor.KeyInfo.X509Data.X509Certificate),
		})
		certs = append(certs, cert)
		diags = append(diags, d...)
	}
	i.X509Certificates, diags = basetypes.NewListValue(x509CertificateType, certs)
	return diags
}

func (i *IdentityProvider) applyDiscovery(ctx context.Context, descriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics

	var ipHints []types.Object
	for _, ipHint := range descriptor.IDPSSODescriptor.Extensions.DiscoHints.IPHints {
		_, ipNet, err := net.ParseCIDR(ipHint)
		if err != nil {
			diags = append(diags, diag.NewWarningDiagnostic(
				fmt.Sprintf("Cannot parse IP hint CIDR from discovery metadata: %s", ipHint),
				err.Error(),
			))
			continue
		}
		ones, _ := ipNet.Mask.Size()
		hint := IPRange{
			BaseIP: basetypes.NewStringValue(ipNet.IP.String()),
			Mask:   basetypes.NewInt32Value(int32(ones)),
		}
		hintObj, d := basetypes.NewObjectValueFrom(ctx, ipRangeType.AttrTypes, hint)
		diags = append(diags, d...)
		ipHints = append(ipHints, hintObj)
	}
	if ipHints == nil {
		ipHints = []types.Object{}
	}
	ipHintValue, d := basetypes.NewListValueFrom(ctx, ipRangeType, ipHints)
	diags = append(diags, d...)

	var domainHints []string
	for _, domainHint := range descriptor.IDPSSODescriptor.Extensions.DiscoHints.DomainHints {
		domainHints = append(domainHints, domainHint)
	}
	if domainHints == nil {
		domainHints = []string{}
	}
	domainHintValue, d := basetypes.NewListValueFrom(ctx, types.StringType, domainHints)
	diags = append(diags, d...)

	var geoHints []types.Object
	for _, geoHint := range descriptor.IDPSSODescriptor.Extensions.DiscoHints.GeloocationHints {
		parts := strings.Split(geoHint, ":")
		if len(parts) != 2 || parts[0] != "geo" {
			diags = append(diags, diag.NewWarningDiagnostic(
				fmt.Sprintf("Cannot parse geolocation hint from discovery metadata: %s", geoHint),
				"Expected format of geo:LATITUDE,LONGITUDE",
			))
			continue
		}
		geoParts := strings.Split(parts[1], ",")
		if len(geoParts) != 2 {
			diags = append(diags, diag.NewWarningDiagnostic(
				fmt.Sprintf("Cannot parse geolocation hint from discovery metadata: %s", geoHint),
				"Expected format of geo:LATITUDE,LONGITUDE",
			))
			continue
		}
		latitude, err := strconv.ParseFloat(geoParts[0], 64)
		if err != nil {
			diags = append(diags, diag.NewWarningDiagnostic(
				fmt.Sprintf("Cannot parse geolocation hint from discovery metadata: %s", geoHint),
				"Expected format of geo:LATITUDE,LONGITUDE ("+err.Error()+")",
			))
			continue
		}
		longitude, err := strconv.ParseFloat(geoParts[1], 64)
		if err != nil {
			diags = append(diags, diag.NewWarningDiagnostic(
				fmt.Sprintf("Cannot parse geolocation hint from discovery metadata: %s", geoHint),
				"Expected format of geo:LATITUDE,LONGITUDE ("+err.Error()+")",
			))
			continue
		}
		hint, d := basetypes.NewObjectValueFrom(ctx, geoLocationType.AttrTypes, GeoLocation{
			Latitude:  basetypes.NewFloat64Value(latitude),
			Longitude: basetypes.NewFloat64Value(longitude),
		})
		diags = append(diags, d...)
		geoHints = append(geoHints, hint)
	}
	if geoHints == nil {
		geoHints = []types.Object{}
	}
	geoHintValue, d := basetypes.NewListValueFrom(ctx, geoLocationType, geoHints)
	diags = append(diags, d...)

	i.Discovery, d = basetypes.NewObjectValueFrom(ctx, discoveryType.AttrTypes, Discovery{
		Domains:      domainHintValue,
		IPRanges:     ipHintValue,
		GeoLocations: geoHintValue,
	})
	diags = append(diags, d...)
	return diags
}

func (i *IdentityProvider) applySingleSignOnServices(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.SingleSignOnServices, diags = i.processServices(ctx, entityDescriptor.IDPSSODescriptor.SingleSignOnServices)
	return diags
}

func (i *IdentityProvider) applySingleLogoutServices(ctx context.Context, entityDescriptor federationtypes.FederationEntityDescriptor) diag.Diagnostics {
	var diags diag.Diagnostics
	i.SingleLogoutServices, diags = i.processServices(ctx, entityDescriptor.IDPSSODescriptor.SingleLogoutServices)
	return diags
}

func (i *IdentityProvider) processServices(ctx context.Context, services []federationtypes.FederationService) (basetypes.ListValue, diag.Diagnostics) {
	var diags diag.Diagnostics
	var svcs []attr.Value
	for _, service := range services {
		svc, d := basetypes.NewObjectValueFrom(ctx, serviceType.AttrTypes, Service{
			basetypes.NewStringValue(service.Binding),
			basetypes.NewStringValue(service.Location),
		})
		svcs = append(svcs, svc)
		diags = append(diags, d...)
	}
	if svcs == nil {
		svcs = []attr.Value{}
	}
	result, d := basetypes.NewListValueFrom(ctx, serviceType, svcs)
	diags = append(diags, d...)
	return result, diags
}

var identityProviderType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"display_names":           types.ListType{ElemType: localizedStringType},
		"descriptions":            types.ListType{ElemType: localizedStringType},
		"information_urls":        types.ListType{ElemType: localizedURLType},
		"privacy_statement_url":   types.ListType{ElemType: localizedURLType},
		"logos":                   types.ListType{ElemType: logoType},
		"registration_info":       registrationInfoType,
		"keywords":                types.ListType{ElemType: localizedStringType},
		"x509_certificates":       types.ListType{ElemType: x509CertificateType},
		"discovery":               discoveryType,
		"single_sign_on_services": types.ListType{ElemType: serviceType},
		"single_logout_services":  types.ListType{ElemType: serviceType},
	},
}

type IdentityProvidersDataSourceModel struct {
	XML                   types.String `tfsdk:"xml"`
	URL                   types.String `tfsdk:"url"`
	RegistrationAuthority types.String `tfsdk:"registration_authority"`
	SigningCertificate    types.String `tfsdk:"signing_certificate"`
	IdentityProviders     types.Map    `tfsdk:"identity_providers"`
}
