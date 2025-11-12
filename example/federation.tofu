provider "samlfederation" {

}

variable "federation_metadata_url" {
  type        = string
  description = "URL of the federation metadata file."
}

variable "federation_registration_authority" {
  type        = string
  description = "Only include identity providers by this registration authority."
  default     = ""
}

variable "federation_signing_certificate" {
  type        = string
  description = "PEM-encoded certificate used to sign the metadata file. This is optional, but strongly recommended."
  default     = ""
}

data "samlfederation_metadata" "eduID" {
  url                    = var.federation_metadata_url
  registration_authority = var.federation_registration_authority
  signing_certificate    = var.federation_signing_certificate
}
