provider "keycloak" {
  client_id     = var.kc_terraform_auth_client_id
  client_secret = var.kc_terraform_auth_password
  url           = var.kc_base_url
  realm         = var.kc_realm
}

# Get Unique ID in keycloak
data "keycloak_realm" "realm" {
  realm = var.kc_realm
}

##############
## IDIR IDP ##
##############

resource "keycloak_oidc_identity_provider" "idir_identity_provider" {
  realm                         = keycloak_realm.realm.id
  provider_id                   = "keycloak-oidc"
  alias                         = "azureidir"
  display_name                  = "New IDIR"
  enabled                       = true
  store_token                   = false
  first_broker_login_flow_alias = "first broker login"
  authorization_url             = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/auth?kc_idp_hint=azureidir"
  token_url                     = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/token"
  logout_url                    = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/logout"
  backchannel_supported         = false
  user_info_url                 = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/userinfo"

  client_id     = "https://dev.oidc.gov.bc.ca/auth/realms/${var.kc_realm}"
  client_secret = "**********"

  issuer             = "https://oidc.gov.bc.ca/auth/realms/_azureidir"
  default_scopes     = "openid profile"
  validate_signature = true

  jwks_url = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/certs"
  extra_config = {
    "clientAuthMethod" = "client_secret_post"
  }
}

############
## Mapper ##
############

resource "keycloak_custom_identity_provider_mapper" "new_idir_displayname" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "displayName"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "displayName"
    UserAttribute = "displayName"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_username" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "username"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-username-idp-mapper"

  extra_config = {
    syncMode = "INHERIT"
    Template = "$${CLAIM.preferred_username}@$${ALIAS}"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_lastname" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "lastName"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "lastName"
    UserAttribute = "lastName"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_idir_userid" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "idir_userid"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "idir_userid"
    UserAttribute = "idir_userid"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_email" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "email"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "email"
    UserAttribute = "email"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_idir_guid" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "idir_guid"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "idir_guid"
    UserAttribute = "idir_guid"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_firstName" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "firstName"
  identity_provider_alias  = keycloak_oidc_identity_provider.idir_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "firstName"
    UserAttribute = "firstName"
  }
}

################
## Github IDP ##
################

resource "keycloak_oidc_identity_provider" "github_identity_provider" {
  realm                         = keycloak_realm.realm.id
  provider_id                   = "keycloak-oidc"
  alias                         = "github"
  display_name                  = "GitHub"
  enabled                       = true
  store_token                   = false
  first_broker_login_flow_alias = "first broker login"
  authorization_url             = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/auth?kc_idp_hint=githubpublic"
  token_url                     = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/token"
  logout_url                    = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/logout"
  backchannel_supported         = true
  user_info_url                 = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/userinfo"

  client_id     = "https://dev.oidc.gov.bc.ca/auth/realms/${var.kc_realm}"
  client_secret = "**********"

  issuer             = "https://oidc.gov.bc.ca/auth/realms/_azureidir"
  default_scopes     = "openid profile"
  validate_signature = true

  jwks_url = "${var.kc_base_url}/auth/realms/standard/protocol/openid-connect/certs"
  extra_config = {
    "clientAuthMethod" = "client_secret_post"
  }
}

############
## Mapper ##
############

resource "keycloak_custom_identity_provider_mapper" "new_idir_displayname" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "displayName"
  identity_provider_alias  = keycloak_oidc_identity_provider.github_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "displayName"
    UserAttribute = "displayName"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_username" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "username"
  identity_provider_alias  = keycloak_oidc_identity_provider.github_identity_provider.alias
  identity_provider_mapper = "%s-oidc-username-idp-mapper"

  extra_config = {
    syncMode = "INHERIT"
    Template = "$${CLAIM.preferred_username}@$${ALIAS}"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_lastname" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "lastName"
  identity_provider_alias  = keycloak_oidc_identity_provider.github_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "lastName"
    UserAttribute = "lastName"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_email" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "email"
  identity_provider_alias  = keycloak_oidc_identity_provider.github_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "email"
    UserAttribute = "email"
  }
}

resource "keycloak_custom_identity_provider_mapper" "new_idir_firstName" {
  realm                    = data.keycloak_realm.realm.id
  name                     = "firstName"
  identity_provider_alias  = keycloak_oidc_identity_provider.github_identity_provider.alias
  identity_provider_mapper = "%s-oidc-user-attribute-idp-mapper"

  extra_config = {
    syncMode      = "INHERIT"
    Claim         = "firstName"
    UserAttribute = "firstName"
  }
}


############
## client ## 
############

resource "keycloak_saml_client" "amazon" {
  realm_id  = keycloak_realm.realm.id
  client_id = "urn:amazon:webservices"
  name      = "AWS LZ0 SAML Client"

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

  signing_certificate = file("resources/saml-cert.pem") // Have to be added or sourced
  signing_private_key = file("resources/saml-key.pem")  // Have to be added or sourced
}

resource "keycloak_generic_client_protocol_mapper" "amazon_mapper_session_name" {
  realm_id        = data.keycloak_realm.realm.id
  client_id       = keycloak_saml_client.amazon.id
  protocol        = "saml"
  name            = "Session Name"
  protocol_mapper = "saml-hardcode-attribute-mapper"
  config = {
    "attribute.value"      = "username"
    "friendly.name"        = "Session Name"
    "attribute.nameformat" = "Basic"
    "attribute.name"       = "https://aws.amazon.com/SAML/Attributes/RoleSessionName"
  }
}

resource "keycloak_generic_client_protocol_mapper" "amazon_mapper_session_role" {
  realm_id        = data.keycloak_realm.realm.id
  client_id       = keycloak_saml_client.amazon.id
  protocol        = "saml"
  name            = "Session Role"
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