# Boundary configuration for the lab. Applied by boundary-terraform on hb01.
# Terraform authenticates with the recovery KMS (a Vault transit key), so no
# bootstrap admin account is needed.

terraform {
  required_version = ">= 1.11"
  required_providers {
    boundary = {
      source  = "hashicorp/boundary"
      version = "1.7.0"
    }
  }
}

provider "boundary" {
  addr             = var.boundary_addr
  recovery_kms_hcl = <<-EOT
    kms "transit" {
      purpose         = "recovery"
      address         = "${var.vault_addr}"
      token           = "${var.kms_token}"
      key_name        = "boundary-recovery"
      mount_path      = "transit/"
      tls_ca_cert     = "${var.ca_cert_file}"
      disable_renewal = "true"
    }
  EOT
}

# ---------------------------------------------------------------------------
# Login. People use OIDC (Keycloak, primary once available). The password
# method holds the break-glass admin and the two service accounts.
# ---------------------------------------------------------------------------
resource "boundary_auth_method_password" "password" {
  scope_id             = "global"
  name                 = "password"
  description          = "Break-glass admin and service accounts"
  is_primary_for_scope = !var.enable_oidc
}

resource "boundary_auth_method_oidc" "keycloak" {
  count = var.enable_oidc ? 1 : 0

  scope_id           = "global"
  name               = "keycloak"
  description        = "Keycloak realm lab (AD users)"
  issuer             = var.oidc_issuer
  client_id          = "boundary"
  client_secret      = var.oidc_client_secret
  signing_algorithms = ["RS256"]
  api_url_prefix     = var.public_addr
  claims_scopes      = ["profile", "email"]
  idp_ca_certs       = [file(var.ca_cert_file)]
  state              = "active-public"
  # Users are created automatically on first login only for the primary method.
  is_primary_for_scope = true

  # Un-set the password method's primary flag first.
  depends_on = [boundary_auth_method_password.password]
}

# One managed group per department, from the Keycloak "groups" claim.
locals {
  departments = toset(flatten([for t in values(var.linux_targets) : t.access]))
}

resource "boundary_managed_group" "department" {
  for_each = var.enable_oidc ? local.departments : toset([])

  auth_method_id = boundary_auth_method_oidc.keycloak[0].id
  name           = each.key
  description    = "AD department ${each.key}"
  filter         = "\"${each.key}\" in \"/token/groups\""
}

# What every logged-in user may do to themselves.
resource "boundary_role" "authenticated" {
  scope_id      = "global"
  name          = "authenticated-self"
  principal_ids = ["u_auth"]
  grant_strings = [
    "ids=*;type=scope;actions=list,no-op",
    "ids={{.Account.Id}};actions=read,change-password",
    "ids=*;type=auth-token;actions=list,read:self,delete:self",
  ]
  grant_scope_ids = ["this", "descendants"]
}

resource "boundary_account_password" "admin" {
  auth_method_id = boundary_auth_method_password.password.id
  login_name     = "admin"
  password       = var.admin_password
}

resource "boundary_user" "admin" {
  scope_id    = "global"
  name        = "admin"
  account_ids = [boundary_account_password.admin.id]
}

resource "boundary_role" "global_admin" {
  scope_id        = "global"
  name            = "global-admin"
  principal_ids   = [boundary_user.admin.id]
  grant_strings   = ["ids=*;type=*;actions=*"]
  grant_scope_ids = ["this", "descendants"]
}

# Read-only account for scripts/boundary_risk_export.py.
resource "boundary_account_password" "risk_exporter" {
  auth_method_id = boundary_auth_method_password.password.id
  login_name     = "risk-exporter"
  password       = var.exporter_password
}

resource "boundary_user" "risk_exporter" {
  scope_id    = "global"
  name        = "risk-exporter"
  description = "Reads targets to export their risk factors"
  account_ids = [boundary_account_password.risk_exporter.id]
}

resource "boundary_role" "risk_exporter" {
  scope_id      = "global"
  name          = "risk-exporter"
  principal_ids = [boundary_user.risk_exporter.id]
  grant_strings = [
    "ids=*;type=scope;actions=list,read",
    "ids=*;type=target;actions=list,read",
    "ids=*;type=host-set;actions=read",
    "ids=*;type=host;actions=read",
  ]
  grant_scope_ids = ["this", "descendants"]
}

# Read-only access for the PAM reviewer on ai01: sessions plus the users,
# accounts (OIDC claims) and targets needed to explain them.
#
# Who holds it: the governed AI agent svc-pam-review (LDAP login, lifecycle
# from midPoint; see the end of this file) once enable_pam_review_agent is on.
# Until then, the LEGACY local pam-reviewer account below, which is removed
# when the switch is turned on.
resource "boundary_account_password" "pam_reviewer" {
  count = var.enable_pam_review_agent ? 0 : 1

  auth_method_id = boundary_auth_method_password.password.id
  login_name     = "pam-reviewer"
  # Only the initial password. After that, hb01's pam-reviewer-rotate job owns
  # it (daily, stored in Vault at secret/boundary/pam-reviewer).
  password = var.reviewer_password

  lifecycle {
    ignore_changes = [password]
  }
}

resource "boundary_user" "pam_reviewer" {
  count = var.enable_pam_review_agent ? 0 : 1

  scope_id    = "global"
  name        = "pam-reviewer"
  description = "ai01 pam-review (legacy local account): reads sessions for risk review"
  account_ids = [boundary_account_password.pam_reviewer[0].id]
}

moved {
  from = boundary_account_password.pam_reviewer
  to   = boundary_account_password.pam_reviewer[0]
}

moved {
  from = boundary_user.pam_reviewer
  to   = boundary_user.pam_reviewer[0]
}

resource "boundary_role" "pam_reviewer" {
  scope_id    = "global"
  name        = "pam-reviewer"
  description = "Read-only session review (ai01 pam-review)"
  # Exactly one of these exists, depending on enable_pam_review_agent.
  principal_ids = concat(boundary_user.pam_review_agent[*].id, boundary_user.pam_reviewer[*].id)
  grant_strings = [
    "ids=*;type=scope;actions=list,read",
    "ids=*;type=session;actions=list,read",
    "ids=*;type=user;actions=list,read",
    "ids=*;type=account;actions=list,read",
    "ids=*;type=auth-method;actions=list,read",
    "ids=*;type=managed-group;actions=list,read",
    "ids=*;type=target;actions=list,read",
    "ids=*;type=host-set;actions=read",
    "ids=*;type=host;actions=read",
  ]
  grant_scope_ids = ["this", "descendants"]
}

resource "boundary_role" "anonymous" {
  scope_id      = "global"
  name          = "anonymous-discovery"
  principal_ids = ["u_anon"]
  grant_strings = [
    "ids=*;type=scope;actions=list,no-op",
    "ids=*;type=auth-method;actions=authenticate,list",
  ]
  grant_scope_ids = ["this", "descendants"]
}

# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------
resource "boundary_scope" "org" {
  scope_id                 = "global"
  name                     = "lab"
  description              = "IAM lab"
  auto_create_admin_role   = false
  auto_create_default_role = false
}

resource "boundary_scope" "linux" {
  scope_id                 = boundary_scope.org.id
  name                     = "linux-targets"
  description              = "lt01-lt05"
  auto_create_admin_role   = false
  auto_create_default_role = false
}

# ---------------------------------------------------------------------------
# Vault credential store + one OTP library per target. Each library POSTs the
# target's IP to Vault, which returns {username, key}; "key" is the one-time
# password. Brokered: the user sees it and enters it at the SSH prompt.
# ---------------------------------------------------------------------------
resource "boundary_credential_store_vault" "hv01" {
  scope_id    = boundary_scope.linux.id
  name        = "hv01"
  description = "Vault on hv01"
  address     = var.vault_addr
  token       = var.credstore_token
  ca_cert     = file(var.ca_cert_file)
}

resource "boundary_credential_library_vault" "otp" {
  for_each = var.linux_targets

  credential_store_id = boundary_credential_store_vault.hv01.id
  name                = "${each.key}-otp"
  description         = "One-time SSH password for ${each.key}"
  path                = "ssh-otp/creds/linux-targets"
  http_method         = "POST"
  http_request_body   = jsonencode({ ip = each.value.ip })
  credential_type     = "username_password"
  credential_mapping_overrides = {
    username_attribute = "username"
    password_attribute = "key"
  }
}

# ---------------------------------------------------------------------------
# Risk metadata. Boundary targets have no custom metadata fields, so it goes
# in the description in a fixed format that the export script parses:
#   "<role> | risk=<1-5> | tier=<tier> | data=<classification> | owners=<dept,...>"
# ---------------------------------------------------------------------------
locals {
  target_descriptions = {
    for name, t in var.linux_targets :
    name => "${t.role} | risk=${t.risk} | tier=${t.tier} | data=${t.data} | owners=${join(",", t.owners)}"
  }
}

# ---------------------------------------------------------------------------
# Hosts and targets. TCP targets, because Boundary's "ssh" target type needs
# credential injection, which is HCP/Enterprise only.
# ---------------------------------------------------------------------------
resource "boundary_host_catalog_static" "linux" {
  scope_id = boundary_scope.linux.id
  name     = "linux-targets"
}

resource "boundary_host_static" "target" {
  for_each = var.linux_targets

  host_catalog_id = boundary_host_catalog_static.linux.id
  name            = each.key
  description     = each.value.role
  address         = each.value.ip
}

resource "boundary_host_set_static" "target" {
  for_each = var.linux_targets

  host_catalog_id = boundary_host_catalog_static.linux.id
  name            = each.key
  host_ids        = [boundary_host_static.target[each.key].id]
}

resource "boundary_target" "ssh" {
  for_each = var.linux_targets

  scope_id                       = boundary_scope.linux.id
  name                           = each.key
  description                    = local.target_descriptions[each.key]
  type                           = "tcp"
  default_port                   = 22
  host_source_ids                = [boundary_host_set_static.target[each.key].id]
  brokered_credential_source_ids = [boundary_credential_library_vault.otp[each.key].id]
}

# ---------------------------------------------------------------------------
# Who may connect: one role per department in the project, granting
# authorize-session on each target whose `access` list includes it.
# ---------------------------------------------------------------------------
resource "boundary_role" "department_access" {
  for_each = boundary_managed_group.department

  scope_id      = boundary_scope.linux.id
  name          = "connect-${lower(each.key)}"
  description   = "${each.key}: connect to ${join(", ", sort([for n, t in var.linux_targets : n if contains(t.access, each.key)]))}"
  principal_ids = [each.value.id]
  grant_strings = concat(
    [
      "ids=*;type=target;actions=list",
      "ids=*;type=session;actions=list,read:self,cancel:self",
    ],
    [
      for n, t in var.linux_targets :
      "ids=${boundary_target.ssh[n].id};actions=read,authorize-session"
      if contains(t.access, each.key)
    ],
  )
  grant_scope_ids = ["this"]
}

# Empty once pam-review uses its governed identity: hb01's rotation job then
# has nothing to rotate and stops.
output "pam_reviewer_account_id" {
  value = try(boundary_account_password.pam_reviewer[0].id, "")
}

output "password_auth_method_id" {
  value = boundary_auth_method_password.password.id
}

output "oidc_auth_method_id" {
  value = var.enable_oidc ? boundary_auth_method_oidc.keycloak[0].id : null
}

# ---------------------------------------------------------------------------
# Ops agent (ag01): non-human identity. It logs in against AD (LDAP), so when
# midPoint disables its AD account (sponsor left, or expired), it can't log in.
# Its password comes from Vault (rotated there) for each task.
# ---------------------------------------------------------------------------
resource "boundary_auth_method_ldap" "ad_agents" {
  # Shared by every AI agent (ops agent, pam-review).
  count = var.enable_agent || var.enable_pam_review_agent ? 1 : 0

  scope_id    = "global"
  name        = "ad-agents"
  description = "AD accounts for non-human identities (OU=AI Agents)"
  urls        = [var.ad_url]
  # Bind as the account itself (user@domain): no search account needed.
  upn_domain   = var.ad_upn_domain
  user_dn      = var.agent_user_dn
  user_attr    = "sAMAccountName"
  certificates = [file(var.ca_cert_file)]
  state        = "active-private"
}

resource "boundary_account_ldap" "agent" {
  count = var.enable_agent ? 1 : 0

  auth_method_id = boundary_auth_method_ldap.ad_agents[0].id
  login_name     = var.agent_account
  name           = var.agent_account
  description    = "Ops agent (ag01); lifecycle from midPoint (AI Agent archetype)"
}

resource "boundary_user" "agent" {
  count = var.enable_agent ? 1 : 0

  scope_id    = "global"
  name        = var.agent_account
  description = "Non-human identity: ops agent on ag01"
  account_ids = [boundary_account_ldap.agent[0].id]
}

# Agent targets: one per host, all five. They broker OTPs for the `agent` user
# (forced into the agent gate on the target). Humans get no grants on these.
resource "boundary_credential_library_vault" "agent_otp" {
  for_each = var.linux_targets

  credential_store_id = boundary_credential_store_vault.hv01.id
  name                = "${each.key}-agent-otp"
  description         = "One-time SSH password for the agent on ${each.key}"
  path                = "ssh-otp/creds/agent-tools"
  http_method         = "POST"
  http_request_body   = jsonencode({ ip = each.value.ip })
  credential_type     = "username_password"
  credential_mapping_overrides = {
    username_attribute = "username"
    password_attribute = "key"
  }
}

resource "boundary_target" "agent" {
  for_each = var.linux_targets

  scope_id                       = boundary_scope.linux.id
  name                           = "${each.key}-agent"
  description                    = "Ops agent access to ${each.key} (named tools only) | ${local.target_descriptions[each.key]}"
  type                           = "tcp"
  default_port                   = 22
  host_source_ids                = [boundary_host_set_static.target[each.key].id]
  brokered_credential_source_ids = [boundary_credential_library_vault.agent_otp[each.key].id]
  session_max_seconds            = 300 # one tool call per session
}

# The agent may connect only to in-scope hosts (agent_scope in targets.nix).
# lt05's agent target exists but isn't granted: Boundary denies it, which is
# logged (hb01 -> Wazuh) and scored by pam-review.
resource "boundary_role" "agent" {
  count = var.enable_agent ? 1 : 0

  scope_id      = boundary_scope.linux.id
  name          = "agent-ops"
  description   = "Ops agent: ${join(", ", sort([for n, t in var.linux_targets : n if t.agent_scope]))}"
  principal_ids = [boundary_user.agent[0].id]
  grant_strings = concat(
    ["ids=*;type=target;actions=list"],
    [
      for n, t in var.linux_targets :
      "ids=${boundary_target.agent[n].id};actions=read,authorize-session"
      if t.agent_scope
    ],
  )
  grant_scope_ids = ["this"]
}

output "agent_auth_method_id" {
  value = var.enable_agent || var.enable_pam_review_agent ? boundary_auth_method_ldap.ad_agents[0].id : null
}

# ---------------------------------------------------------------------------
# pam-review (ai01): the AI PAM reviewer as a governed non-human identity.
# Same LDAP login as the ops agent, so when midPoint disables its AD account
# (sponsor left, or expired) it can't log in. Its grants are the read-only
# pam-reviewer role above; it gets no targets and can't open sessions.
# ---------------------------------------------------------------------------
resource "boundary_account_ldap" "pam_review_agent" {
  count = var.enable_pam_review_agent ? 1 : 0

  auth_method_id = boundary_auth_method_ldap.ad_agents[0].id
  login_name     = var.pam_review_account
  name           = var.pam_review_account
  description    = "AI PAM reviewer (ai01); lifecycle from midPoint (AI Agent archetype)"
}

resource "boundary_user" "pam_review_agent" {
  count = var.enable_pam_review_agent ? 1 : 0

  scope_id    = "global"
  name        = var.pam_review_account
  description = "Non-human identity: AI PAM reviewer on ai01 (read-only)"
  account_ids = [boundary_account_ldap.pam_review_agent[0].id]
}
