# Vault configuration for the lab. Applied by vault-bootstrap on hv01 with
# VAULT_ADDR / VAULT_TOKEN from the environment.

terraform {
  required_version = ">= 1.11" # write-only attributes (bindpass_wo)
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.13.0"
    }
  }
}

provider "vault" {}

locals {
  token_self_policy = <<-EOT
    path "auth/token/lookup-self"  { capabilities = ["read"] }
    path "auth/token/renew-self"   { capabilities = ["update"] }
    path "auth/token/revoke-self"  { capabilities = ["update"] }
    path "sys/leases/renew"        { capabilities = ["update"] }
    path "sys/leases/revoke"       { capabilities = ["update"] }
    path "sys/capabilities-self"   { capabilities = ["update"] }
  EOT
}

# ---------------------------------------------------------------------------
# Audit device: one JSON line per request and per response, so every
# credential read, approval signature and policy change is attributable.
# Vault HMACs secret values (passwords, tokens) before writing them, so the
# log never holds a usable credential. It fails closed: if Vault can't write
# here, it refuses the request. hv01 forwards the file to Wazuh (wz01).
# ---------------------------------------------------------------------------
resource "vault_audit" "file" {
  type        = "file"
  path        = "file"
  description = "Audit trail, forwarded to Wazuh"
  options = {
    file_path = var.audit_log_path
    mode      = "0600"
  }
}

# ---------------------------------------------------------------------------
# Transit: Boundary's KMS keys. Vault rotates them on a schedule; old key
# versions stay available for decryption, so Boundary never notices.
# ---------------------------------------------------------------------------
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "KMS keys for Boundary (hb01)"
}

resource "vault_transit_secret_backend_key" "boundary" {
  for_each = toset(["boundary-root", "boundary-worker-auth", "boundary-recovery"])

  backend            = vault_mount.transit.path
  name               = each.key
  type               = "aes256-gcm96"
  auto_rotate_period = var.transit_rotate_seconds
  deletion_allowed   = false
}

resource "vault_policy" "boundary_kms" {
  name   = "boundary-kms"
  policy = <<-EOT
    path "transit/encrypt/boundary-*" { capabilities = ["update"] }
    path "transit/decrypt/boundary-*" { capabilities = ["update"] }
    ${local.token_self_policy}
  EOT
}

# ---------------------------------------------------------------------------
# SSH one-time passwords for the Linux targets. Boundary requests one per
# session (brokered credential); vault-ssh-helper on the target verifies it.
# ---------------------------------------------------------------------------
resource "vault_mount" "ssh_otp" {
  path        = "ssh-otp"
  type        = "ssh"
  description = "One-time SSH passwords for lt01-lt05"
}

resource "vault_ssh_secret_backend_role" "linux_targets" {
  backend       = vault_mount.ssh_otp.path
  name          = "linux-targets"
  key_type      = "otp"
  default_user  = var.target_user
  allowed_users = var.target_user
  cidr_list     = join(",", [for t in values(var.linux_targets) : "${t.ip}/32"])
}

resource "vault_policy" "boundary_credstore" {
  name   = "boundary-credstore"
  policy = <<-EOT
    path "${vault_mount.ssh_otp.path}/creds/${vault_ssh_secret_backend_role.linux_targets.name}" {
      capabilities = ["create", "update"]
    }
    path "${vault_mount.ssh_otp.path}/creds/${vault_ssh_secret_backend_role.agent_tools.name}" {
      capabilities = ["create", "update"]
    }
    ${local.token_self_policy}
  EOT
}

# ---------------------------------------------------------------------------
# Token roles for Boundary. Boundary requires orphan, periodic, renewable
# tokens; it renews them itself, so they live as long as Boundary is running.
# ---------------------------------------------------------------------------
resource "vault_token_auth_backend_role" "boundary" {
  for_each = {
    "boundary-kms"       = vault_policy.boundary_kms.name
    "boundary-credstore" = vault_policy.boundary_credstore.name
  }

  role_name        = each.key
  allowed_policies = [each.value]
  orphan           = true
  renewable        = true
  token_period     = var.boundary_token_period
}

# ---------------------------------------------------------------------------
# AD service accounts: Vault owns and rotates their passwords (LDAP secrets
# engine, static roles). Consumers read the current password via Vault Agent.
# Off until enable_ad_rotation = true (see lab.auto.tfvars).
# ---------------------------------------------------------------------------
resource "vault_auth_backend" "approle" {
  type = "approle"
}

resource "vault_password_policy" "ad" {
  name   = "ad"
  policy = <<-EOT
    length = 32
    rule "charset" {
      charset   = "abcdefghijklmnopqrstuvwxyz"
      min-chars = 2
    }
    rule "charset" {
      charset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      min-chars = 2
    }
    rule "charset" {
      charset   = "0123456789"
      min-chars = 2
    }
    rule "charset" {
      charset   = "!@#%^*-_=+"
      min-chars = 2
    }
  EOT
}

resource "vault_ldap_secret_backend" "ad" {
  # Also needed for the AI agents' AD accounts (enable_agent,
  # enable_pam_review_agent), even when the human service accounts aren't rotated.
  count = var.enable_ad_rotation || var.enable_agent || var.enable_pam_review_agent ? 1 : 0

  path            = "ldap"
  schema          = "ad"
  url             = var.ad_url
  binddn          = var.ad_bind_dn
  userdn          = var.ad_user_dn
  userattr        = "sAMAccountName"
  certificate     = file(var.ad_ca_file)
  password_policy = vault_password_policy.ad.name

  # Write-only: read once from the file, never stored in state. Vault rotates
  # this password itself afterwards, so the file is only used for setup.
  # Bump the version to push a new bootstrap password.
  bindpass_wo         = trimspace(file(var.ad_bind_password_file))
  bindpass_wo_version = 1
}

resource "vault_ldap_secret_backend_static_role" "ad" {
  for_each = var.enable_ad_rotation ? var.ad_rotated_accounts : {}

  mount           = vault_ldap_secret_backend.ad[0].path
  role_name       = each.key
  username        = each.key
  dn              = each.value
  rotation_period = var.ad_rotation_seconds
}

# One AppRole per consuming container, allowed to read only its own account.
resource "vault_policy" "ad_consumer" {
  for_each = var.enable_ad_rotation ? var.ad_consumers : {}

  name   = "${each.key}-ad"
  policy = <<-EOT
    path "ldap/static-cred/${each.value}" { capabilities = ["read"] }
  EOT
}

resource "vault_approle_auth_backend_role" "ad_consumer" {
  for_each = var.enable_ad_rotation ? var.ad_consumers : {}

  backend        = vault_auth_backend.approle.path
  role_name      = each.key
  token_policies = [vault_policy.ad_consumer[each.key].name]
  token_ttl      = 3600
  token_max_ttl  = 14400
  secret_id_ttl  = 0
}

# ---------------------------------------------------------------------------
# Human login: OIDC via Keycloak. The AD department arrives as the "groups"
# claim; each department maps to an external identity group with policies.
# The root token in init.json is break-glass only.
# ---------------------------------------------------------------------------
resource "vault_policy" "lab" {
  for_each = var.oidc_policies

  name   = each.key
  policy = each.value
}

resource "vault_jwt_auth_backend" "oidc" {
  count = var.enable_oidc ? 1 : 0

  path                  = "oidc"
  type                  = "oidc"
  description           = "Keycloak (realm lab)"
  oidc_discovery_url    = var.oidc_issuer
  oidc_discovery_ca_pem = file(var.ad_ca_file)
  oidc_client_id        = var.oidc_client_id
  oidc_client_secret_wo = var.oidc_client_secret
  # Bump when hv01 issues a new client secret.
  oidc_client_secret_wo_version = 1
  default_role                  = "default"

  tune {
    listing_visibility = "unauth" # show "OIDC" on the UI login page
    default_lease_ttl  = "1h"
    max_lease_ttl      = "8h"
    token_type         = "default-service"
  }
}

resource "vault_jwt_auth_backend_role" "default" {
  count = var.enable_oidc ? 1 : 0

  backend         = vault_jwt_auth_backend.oidc[0].path
  role_name       = "default"
  role_type       = "oidc"
  user_claim      = "preferred_username"
  groups_claim    = "groups"
  oidc_scopes     = ["openid", "profile", "email"]
  bound_audiences = [var.oidc_client_id]
  allowed_redirect_uris = [
    "https://hv01.lab.internal/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8250/oidc/callback",
  ]
  token_ttl     = 3600
  token_max_ttl = 28800
}

resource "vault_identity_group" "department" {
  for_each = var.enable_oidc ? var.oidc_group_policies : {}

  name     = "dept-${lower(each.key)}"
  type     = "external"
  policies = each.value
  metadata = { department = each.key }

  depends_on = [vault_policy.lab, vault_policy.agent_approver]
}

resource "vault_identity_group_alias" "department" {
  for_each = vault_identity_group.department

  name           = each.value.metadata.department # value of the "groups" claim
  mount_accessor = vault_jwt_auth_backend.oidc[0].accessor
  canonical_id   = each.value.id
}

# ---------------------------------------------------------------------------
# pam-reviewer: the LEGACY Boundary credential ai01's pam-review logs in with,
# until it moves to its governed identity (enable_pam_review_agent, below).
# Everything in this section is removed when that is on.
#
# Approach (recorded in docs/vault-boundary.md):
# - The password lives only in Vault KV at secret/boundary/pam-reviewer.
# - hb01 rotates it daily: sets a new password on the Boundary account (via
#   the recovery KMS) and writes it here. Its AppRole may only write this path.
# - ai01 reads it at the start of every review run with an AppRole token that
#   lives 5 minutes and is revoked right after; the password is never stored
#   on ai01's disk. Its AppRole may only read this path.
# - Both AppRoles (secret IDs and tokens) only work from their own container's
#   IP, so a copied secret_id is useless anywhere else.
# Vault has no Boundary secrets engine, so this is rotation by a scheduled
# job with Vault as the single source of truth, not a dynamic secret.
# ---------------------------------------------------------------------------
resource "vault_mount" "kv" {
  count = var.enable_pam_review_agent ? 0 : 1

  path        = "secret"
  type        = "kv"
  options     = { version = "2" }
  description = "Static secrets rotated by lab jobs"
}

resource "vault_kv_secret_backend_v2" "kv" {
  count = var.enable_pam_review_agent ? 0 : 1

  mount        = vault_mount.kv[0].path
  max_versions = 5
}

locals {
  pam_reviewer_path = "secret/data/boundary/pam-reviewer"
}

moved {
  from = vault_mount.kv
  to   = vault_mount.kv[0]
}

moved {
  from = vault_kv_secret_backend_v2.kv
  to   = vault_kv_secret_backend_v2.kv[0]
}

moved {
  from = vault_policy.pam_reviewer_read
  to   = vault_policy.pam_reviewer_read[0]
}

moved {
  from = vault_policy.pam_reviewer_rotate
  to   = vault_policy.pam_reviewer_rotate[0]
}

resource "vault_policy" "pam_reviewer_read" {
  count = var.enable_pam_review_agent ? 0 : 1

  name   = "pam-reviewer-read"
  policy = <<-EOT
    path "${local.pam_reviewer_path}" { capabilities = ["read"] }
  EOT
}

resource "vault_policy" "pam_reviewer_rotate" {
  count = var.enable_pam_review_agent ? 0 : 1

  name   = "pam-reviewer-rotate"
  policy = <<-EOT
    path "${local.pam_reviewer_path}" { capabilities = ["create", "update", "read"] }
  EOT
}

# Role names match the container names: hv01 hands role_id/secret_id to
# handoff/<role>/ (see vault-bootstrap).
resource "vault_approle_auth_backend_role" "pam_reviewer" {
  for_each = var.enable_pam_review_agent ? {} : {
    ai01 = { policy = vault_policy.pam_reviewer_read[0].name, cidr = var.ai01_ip }
    hb01 = { policy = vault_policy.pam_reviewer_rotate[0].name, cidr = var.hb01_ip }
  }

  backend               = vault_auth_backend.approle.path
  role_name             = each.key
  token_policies        = [each.value.policy]
  token_ttl             = 300
  token_max_ttl         = 300
  token_bound_cidrs     = ["${each.value.cidr}/32"]
  secret_id_bound_cidrs = ["${each.value.cidr}/32"]
  secret_id_ttl         = 0
}

# ---------------------------------------------------------------------------
# Ops agent (ag01): a governed non-human identity. See docs/ops-agent.md.
#
#   Keycloak client credentials (ops-agent) -> Vault JWT login (10 min, can
#   only read its own AD password) -> Boundary LDAP login -> brokered OTP for
#   the `agent` user on in-scope targets. The AD account's lifecycle comes from
#   midPoint (sponsor + expiry); Vault owns and rotates its password.
# ---------------------------------------------------------------------------

# One-time passwords for the `agent` account on the targets (forced into the
# agent gate there). Separate role from humans' `ops`.
resource "vault_ssh_secret_backend_role" "agent_tools" {
  backend       = vault_mount.ssh_otp.path
  name          = "agent-tools"
  key_type      = "otp"
  default_user  = "agent"
  allowed_users = "agent"
  cidr_list     = join(",", [for t in values(var.linux_targets) : "${t.ip}/32" if t.agent_scope])
}

# Human approvals for the agent's Tier 1 actions: ed25519 signatures, verified
# on the targets with the public keys hv01 exports (all versions).
resource "vault_transit_secret_backend_key" "agent_approvals" {
  backend            = vault_mount.transit.path
  name               = "agent-approvals"
  type               = "ed25519"
  auto_rotate_period = var.transit_rotate_seconds
  deletion_allowed   = false
}

resource "vault_policy" "agent_approver" {
  name   = "agent-approver"
  policy = <<-EOT
    path "transit/sign/agent-approvals" { capabilities = ["update"] }
  EOT
}

# The agent's own password, rotated by Vault (it owns it; midPoint only
# creates/enables/disables the account).
resource "vault_ldap_secret_backend_static_role" "agent" {
  count = var.enable_agent ? 1 : 0

  mount           = vault_ldap_secret_backend.ad[0].path
  role_name       = var.agent_account
  username        = var.agent_account
  dn              = var.agent_account_dn
  rotation_period = var.agent_rotation_seconds
}

resource "vault_policy" "agent_ops" {
  name   = "agent-ops"
  policy = <<-EOT
    path "ldap/static-cred/${var.agent_account}" { capabilities = ["read"] }
    path "auth/token/revoke-self"              { capabilities = ["update"] }
  EOT
}

# Workload login: Keycloak-issued client-credentials tokens for ops-agent.
resource "vault_jwt_auth_backend" "keycloak_workloads" {
  count = var.enable_oidc ? 1 : 0

  path                  = "jwt-keycloak"
  type                  = "jwt"
  description           = "Keycloak workload identities (client credentials)"
  oidc_discovery_url    = var.oidc_issuer
  oidc_discovery_ca_pem = file(var.ad_ca_file)
  bound_issuer          = var.oidc_issuer
}

resource "vault_jwt_auth_backend_role" "ops_agent" {
  count = var.enable_oidc ? 1 : 0

  backend         = vault_jwt_auth_backend.keycloak_workloads[0].path
  role_name       = "ops-agent"
  role_type       = "jwt"
  bound_audiences = ["vault-agents"]
  bound_claims    = { azp = "ops-agent" }
  user_claim      = "azp"
  token_policies  = [vault_policy.agent_ops.name]
  token_ttl       = 600
  token_max_ttl   = 600
  token_type      = "service"
}

# ---------------------------------------------------------------------------
# pam-review (ai01): the AI PAM reviewer as a governed non-human identity, the
# same chain as the ops agent. See docs/ai-pam.md ("Governed identity").
#
#   Keycloak client credentials (pam-review) -> Vault JWT login (10 min, can
#   only read its own AD password) -> Boundary LDAP login as svc-pam-review
#   -> read-only role. midPoint (AI Agent archetype) owns the AD account's
#   lifecycle (sponsor + expiry); Vault owns and rotates its password.
# ---------------------------------------------------------------------------
resource "vault_ldap_secret_backend_static_role" "pam_review" {
  count = var.enable_pam_review_agent ? 1 : 0

  mount           = vault_ldap_secret_backend.ad[0].path
  role_name       = var.pam_review_account
  username        = var.pam_review_account
  dn              = var.pam_review_account_dn
  rotation_period = var.agent_rotation_seconds
}

resource "vault_policy" "pam_review_agent" {
  count = var.enable_pam_review_agent ? 1 : 0

  name   = "pam-review-agent"
  policy = <<-EOT
    path "ldap/static-cred/${var.pam_review_account}" { capabilities = ["read"] }
    path "auth/token/revoke-self"                   { capabilities = ["update"] }
  EOT
}

resource "vault_jwt_auth_backend_role" "pam_review" {
  count = var.enable_oidc && var.enable_pam_review_agent ? 1 : 0

  backend         = vault_jwt_auth_backend.keycloak_workloads[0].path
  role_name       = "pam-review"
  role_type       = "jwt"
  bound_audiences = ["vault-agents"]
  bound_claims    = { azp = "pam-review" }
  user_claim      = "azp"
  token_policies  = [vault_policy.pam_review_agent[0].name]
  token_ttl       = 600
  token_max_ttl   = 600
  token_type      = "service"
}
