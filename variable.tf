variable "kc_base_url" {
  description = "Base URL for Keycloak"
}

variable "kc_realm" {
  default = "public-cloud"
  description = "realm name for Keycloak"
}

variable "kc_terraform_auth_client_id" {
  default = "terraform"
  description = "Keycloal progamatic user name"
}

variable "kc_terraform_auth_password" {
  description = "Keycloal progamatic password"
}

variable "cloudfront_auth_url" {
  description = "Authentication portal Cloudfront url"
}