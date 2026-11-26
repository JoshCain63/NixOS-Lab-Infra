# Keycloak OIDC clients in the existing "lab" realm: Boundary, Vault, the
# Wazuh dashboard (SOC), ai01's PAM review report, and the two AI agents'
# workload clients (ops-agent, pam-review).
# Applied by keycloak-terraform on idp01. Client secrets are generated on hv01
# and handed over as files, so they never enter this repo or the state.

terraform {
  required_version = ">= 1.11"
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "5.10.0"
    }
  }
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = var.admin_username
  password  = var.admin_password
  url       = var.keycloak_url
  realm     = "master"
}

data "keycloak_realm" "lab" {
  realm = "lab"
}

locals {
  clients = {
    boundary = {
      name = "HashiCorp Boundary (hb01)"
      redirect_uris = [
        "https://hb01.lab.internal/v1/auth-methods/oidc:authenticate:callback",
      ]
    }
    vault = {
      name = "HashiCorp Vault (hv01)"
      redirect_uris = [
        "https://hv01.lab.internal/ui/vault/auth/oidc/oidc/callback",
        "http://localhost:8250/oidc/callback", # vault login -method=oidc
      ]
    }
    # Access to these two is limited to IT by the apps themselves (indexer
    # roles mapping / oauth2-proxy allowed-group), from the groups claim.
    wazuh = {
      name          = "Wazuh dashboard (wz01, SOC)"
      redirect_uris = ["https://wz01.lab.internal/auth/openid/login"]
    }
    pam-report = {
      name          = "PAM review report (ai01)"
      redirect_uris = ["https://ai01.lab.internal/oauth2/callback"]
    }
  }
}

resource "keycloak_openid_client" "client" {
  for_each = local.clients

  realm_id                     = data.keycloak_realm.lab.id
  client_id                    = each.key
  name                         = each.value.name
  access_type                  = "CONFIDENTIAL"
  standard_flow_enabled        = true
  direct_access_grants_enabled = false
  valid_redirect_uris          = each.value.redirect_uris

  # Write-only: never stored in state. Bump the version if hv01 issues a new one.
  client_secret_wo         = trimspace(file("${var.secrets_dir}/${each.key}-oidc-secret"))
  client_secret_wo_version = 1
}

# Department (from AD via LDAP federation) -> multivalued "groups" claim,
# the same claim oauth2-proxy already uses.
resource "keycloak_openid_user_attribute_protocol_mapper" "groups" {
  for_each = local.clients

  realm_id            = data.keycloak_realm.lab.id
  client_id           = keycloak_openid_client.client[each.key].id
  name                = "department-to-groups"
  user_attribute      = var.department_attribute
  claim_name          = "groups"
  multivalued         = true
  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# ---------------------------------------------------------------------------
# AI agents: workload identities, not people. Client credentials only (no
# browser login, no user session), 5-minute tokens, and an audience that only
# Vault's agent JWT roles accept. Each agent's AD account and its lifecycle
# (sponsor + expiry) come from midPoint's AI Agent archetype.
# ---------------------------------------------------------------------------
locals {
  agent_clients = {
    ops-agent  = "Ops agent (ag01, non-human identity)"
    pam-review = "AI PAM reviewer (ai01, non-human identity)"
  }
}

resource "keycloak_openid_client" "agent" {
  for_each = local.agent_clients

  realm_id                     = data.keycloak_realm.lab.id
  client_id                    = each.key
  name                         = each.value
  access_type                  = "CONFIDENTIAL"
  service_accounts_enabled     = true
  standard_flow_enabled        = false
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  access_token_lifespan        = "300"

  client_secret_wo         = trimspace(file("${var.secrets_dir}/${each.key}-oidc-secret"))
  client_secret_wo_version = 1
}

resource "keycloak_openid_audience_protocol_mapper" "agent_vault" {
  for_each = local.agent_clients

  realm_id                 = data.keycloak_realm.lab.id
  client_id                = keycloak_openid_client.agent[each.key].id
  name                     = "audience-vault-agents"
  included_custom_audience = "vault-agents"
  add_to_access_token      = true
  add_to_id_token          = false
}

moved {
  from = keycloak_openid_client.ops_agent
  to   = keycloak_openid_client.agent["ops-agent"]
}

moved {
  from = keycloak_openid_audience_protocol_mapper.ops_agent_vault
  to   = keycloak_openid_audience_protocol_mapper.agent_vault["ops-agent"]
}
