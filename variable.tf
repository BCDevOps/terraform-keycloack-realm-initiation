variable "kc_terraform_auth_client_id" {
  description = "Id of client used to connect to keycloack"
}

variable "kc_terraform_auth_client_secret" {
  description = "secret of client used to connect to keycloack"
}

variable "kc_base_url" {
  description = "Base URL for Keycloak example: "
}

variable "kc_realm" {
  default = "public-cloud"
  description = "realm name for Keycloak"
}

variable "saml_client_display_name" {
  description = "Displayed name on the saml AWS client login page"
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

variable "role_names" {
  description = "List of Keycloak role names"
  type        = list(string)
  default     = ["manage-users", "query-groups"]
}


