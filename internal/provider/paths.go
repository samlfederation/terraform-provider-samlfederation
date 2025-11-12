package provider

import "github.com/hashicorp/terraform-plugin-framework/path"

var signingCertificatePath = path.Root("signing_certificate")
var xmlPath = path.Root("xml")
var urlPath = path.Root("url")
var registrationAuthorityPath = path.Root("registration_authority")
var identityProvidersPath = path.Root("identity_providers")
