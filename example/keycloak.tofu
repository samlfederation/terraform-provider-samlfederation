variable "keycloak_url" {
  description = "Keycloak URL"
  type        = string
}

variable "keycloak_realm" {
  description = "Keycloak Realm name"
  type        = string
}

variable "keycloak_client_id" {
  description = "Client ID for Keycloak API access"
  type        = string
  default     = ""
}

variable "keycloak_client_secret" {
  description = "Client secret for Keycloak API access"
  type        = string
  sensitive   = true
  default     = ""
}

variable "keycloak_username" {
  description = "Username for Keycloak API access"
  type        = string
  default     = ""
}

variable "keycloak_password" {
  description = "Password for Keycloak API access"
  type        = string
  sensitive   = true
  default     = ""
}


provider "keycloak" {
  client_id     = var.keycloak_client_id
  client_secret = var.keycloak_client_secret
  username      = var.keycloak_username
  password      = var.keycloak_password
  url           = var.keycloak_url
}

data "keycloak_realm" "realm" {
  realm = var.keycloak_realm
}

resource "keycloak_saml_identity_provider" "eduid" {
  realm    = data.keycloak_realm.realm.id
  for_each = data.samlfederation_metadata.eduID.identity_providers

  alias                      = each.key
  display_name               = each.value["display_name"]
  entity_id                  = each.key
  single_sign_on_service_url = each.value["sso_service_url"]
  single_logout_service_url  = each.value["sso_logout_service_url"]

  backchannel_supported      = each.value["backchannel_supported"]
  post_binding_response      = each.value["post_binding_response"]
  post_binding_logout        = each.value["post_binding_logout"]
  post_binding_authn_request = each.value["post_binding_authn_request"]
  want_assertions_signed     = each.value["want_assertions_signed"]
  want_assertions_encrypted  = each.value["want_assertions_encrypted"]
  validate_signature         = each.value["validate_signature"]
}