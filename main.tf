# Get Unique ID in keycloak
data "keycloak_realm" "realm" {
  realm = var.kc_realm
}

##############
## IDIR IDP ##
##############

resource "keycloak_oidc_identity_provider" "idir_identity_provider" {
  realm                         = data.keycloak_realm.realm.id
  provider_id                   = "oidc"
  alias                         = "azureidir"
  display_name                  = "Azure AD OIDC"
  enabled                       = true
  store_token                   = false
  first_broker_login_flow_alias = "first broker login"
  sync_mode                     = "FORCE"
  authorization_url             = "${var.kc_base_url}/realms/standard/protocol/openid-connect/auth?kc_idp_hint=azureidir"
  token_url                     = "${var.kc_base_url}/realms/standard/protocol/openid-connect/token"
  logout_url                    = "${var.kc_base_url}/realms/standard/protocol/openid-connect/logout"
  backchannel_supported         = false
  user_info_url                 = "${var.kc_base_url}/realms/standard/protocol/openid-connect/userinfo"

  client_id     = var.client_id
  client_secret = var.client_secret

  # issuer             = "${var.kc_base_url}/realms/_azureidir"
  default_scopes     = "openid profile"
  validate_signature = true

  jwks_url = "${var.kc_base_url}/realms/standard/protocol/openid-connect/certs"
  extra_config = {
    "clientAuthMethod" = "client_secret_post"
  }
}

############
## Mapper ##
############

resource "keycloak_custom_identity_provider_mapper" "new_idir_displayname" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "display_name"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "oidc-user-attribute-idp-mapper"

  extra_config = {
    "syncMode"       = "FORCE"
    "claim"          = "display_name"
    "user.attribute" = "display_name"
  }
}


resource "keycloak_custom_identity_provider_mapper" "new_idir_idir_userid" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "idir_user_guid"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "oidc-user-attribute-idp-mapper"

  extra_config = {
    "syncMode"       = "FORCE"
    "claim"          = "idir_user_guid"
    "user.attribute" = "idir_user_guid"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_idir_guid" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "idir_username"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "oidc-user-attribute-idp-mapper"

  extra_config = {
    "syncMode"       = "FORCE"
    "claim"          = "idir_username"
    "user.attribute" = "idir_username"
  }
}

############
## client ## 
############

resource "keycloak_saml_client" "amazon" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = "urn:amazon:webservices"
  name      = var.saml_client_display_name

  sign_documents          = true
  sign_assertions         = true
  include_authn_statement = true

  name_id_format = "persistent"

  signature_algorithm     = "RSA_SHA256"
  signature_key_name      = "KEY_ID"
  canonicalization_method = "EXCLUSIVE"

  valid_redirect_uris = [
    "https://signin.aws.amazon.com/saml",
    "${var.cloudfront_auth_url}",
    "/auth/realms/${var.kc_realm}/protocol/saml/clients/amazon-aws"
  ]

  base_url = "/auth/realms/${var.kc_realm}/protocol/saml/clients/amazon-aws"

  idp_initiated_sso_url_name = "amazon-aws"

  assertion_consumer_post_url = var.cloudfront_auth_url
  full_scope_allowed          = false

  extra_config = {
    "saml.assertion.lifespan" = 300
  }
}

resource "keycloak_generic_client_protocol_mapper" "amazon_mapper_session_name" {
  realm_id        = data.keycloak_realm.realm.id
  client_id       = keycloak_saml_client.amazon.id
  protocol        = "saml"
  name            = "Session Name"
  protocol_mapper = "saml-user-property-mapper"
  config = {
    "user.attribute"       = "username"
    "friendly.name"        = "Session Name"
    "attribute.nameformat" = "Basic"
    "attribute.name"       = "https://aws.amazon.com/SAML/Attributes/RoleSessionName"
  }
}

resource "keycloak_generic_client_protocol_mapper" "amazon_mapper_session_role" {
  realm_id        = data.keycloak_realm.realm.id
  client_id       = keycloak_saml_client.amazon.id
  protocol        = "saml"
  name            = "https://aws.amazon.com/SAML/Attributes/Role"
  protocol_mapper = "saml-role-list-mapper"
  config = {
    "single"               = true
    "friendly.name"        = "Session Role"
    "attribute.nameformat" = "Basic"
    "attribute.name"       = "https://aws.amazon.com/SAML/Attributes/Role"
  }
}

resource "keycloak_generic_client_protocol_mapper" "amazon_mapper_session_duration" {
  realm_id        = data.keycloak_realm.realm.id
  client_id       = keycloak_saml_client.amazon.id
  protocol        = "saml"
  name            = "Session Duration"
  protocol_mapper = "saml-hardcode-attribute-mapper"
  config = {
    "attribute.value"      = 28800
    "friendly.name"        = "Session Duration"
    "attribute.nameformat" = "Basic"
    "attribute.name"       = "https://aws.amazon.com/SAML/Attributes/SessionDuration"
  }
}

resource "keycloak_openid_client" "user_managemennt_client" {
  client_id                           = "user_management"
  name                                = "user_management"
  realm_id                            = data.keycloak_realm.realm.id
  description                         = "Client with Scoped perms to manage users through registry"
  enabled                             = true
  full_scope_allowed                  = false
  standard_flow_enabled               = false
  service_accounts_enabled            = true
  backchannel_logout_session_required = true
  access_type                         = "CONFIDENTIAL"
}

data "keycloak_openid_client" "realm_management" {
  realm_id  = data.keycloak_realm.realm.id
  client_id = "realm-management"
}

data "keycloak_role" "roles" {
  for_each = toset(var.role_names)

  realm_id  = data.keycloak_realm.realm.id
  client_id = data.keycloak_openid_client.realm_management.id
  name      = each.value
}


resource "keycloak_role" "user_management_roles" {
  name      = "user_management_roles"
  realm_id  = data.keycloak_realm.realm.id
  client_id = keycloak_openid_client.user_managemennt_client.id

  composite_roles = [for role in var.role_names : data.keycloak_role.roles[role].id]
}


resource "keycloak_openid_client_service_account_role" "user_managemennt_service_account_role" {
  realm_id                = data.keycloak_realm.realm.id
  service_account_user_id = keycloak_openid_client.user_managemennt_client.service_account_user_id
  client_id               = keycloak_openid_client.user_managemennt_client.id
  role                    = keycloak_role.user_management_roles.name
}
