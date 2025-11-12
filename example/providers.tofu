terraform {
  required_providers {
    keycloak = {
      source = "keycloak/keycloak"
      version = "5.5.0"
    }
    samlfederation = {
      source = "registry.opentofu.org/samlfederation/samlfederation"
    }
  }
}