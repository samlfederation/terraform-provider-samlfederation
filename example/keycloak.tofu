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

  alias                      = replace(replace(each.key, ":", "_"), "/", "_")
  display_name               = jsonencode({
    "name": {for name in each.value.display_names : name.language => name.text},
  })
  entity_id                  = each.key
  single_sign_on_service_url = each.value.single_sign_on_services[0].location
  single_logout_service_url  = length(each.value.single_logout_services) > 0?each.value.single_logout_services[0].location:null

  backchannel_supported      = length(each.value.single_logout_services) > 0
  post_binding_response      = each.value.single_sign_on_services[0].binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  post_binding_logout        = length(each.value.single_logout_services) > 0?each.value.single_logout_services[0].binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":false
  post_binding_authn_request = each.value.single_sign_on_services[0].binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
}
