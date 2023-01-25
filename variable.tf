variable "kc_base_url" {
  default = "https://dev.loginproxy.gov.bc.ca"
  description = "Base URL for Keycloak example: "
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

variable "client_id" {
  description = "Client id for the IDP OIDC Configuration, this is given from the OIDC integration request"
}


variable "client_secret" {
  description = "Client secret for the IDP OIDC Configuration, this is given from the OIDC integration request"
}



