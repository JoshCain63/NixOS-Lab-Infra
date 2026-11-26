variable "linux_targets" {
  description = "Targets from hosts/lab/targets.nix (generated targets.auto.tfvars.json)."
  type = map(object({
    ip     = string
    risk   = number
    tier   = string
    role   = string
    data   = string
    owners      = list(string)
    access      = list(string)
    agent_scope = bool
  }))
}

variable "target_user" {
  description = "Local account on the Linux targets that OTP sessions log in as."
  type        = string
  default     = "ops"
}

variable "transit_rotate_seconds" {
  description = "How often Vault rotates Boundary's transit KMS keys."
  type        = number
  default     = 2592000 # 30 days
}

variable "audit_log_path" {
  description = "Vault's file audit device. Must match hv01.nix (LogsDirectory, rsyslog, logrotate)."
  type        = string
  default     = "/var/log/vault/audit.log"
}

variable "boundary_token_period" {
  description = "Renewal period for Boundary's tokens. Re-issued on boot if the lab was off longer."
  type        = number
  default     = 604800 # 7 days
}

# --- AD password rotation ---------------------------------------------------

variable "enable_ad_rotation" {
  description = "Turn on the LDAP secrets engine for AD service accounts."
  type        = bool
  default     = false
}

variable "ad_url" {
  type    = string
  default = "ldaps://win-srv01.ad.lab.internal"
}

variable "ad_bind_dn" {
  description = "DN of the account Vault binds as (needs Reset Password on the rotated accounts)."
  type        = string
  default     = ""
}

variable "ad_user_dn" {
  description = "Base DN Vault searches for the rotated accounts."
  type        = string
  default     = ""
}

variable "ad_bind_password_file" {
  description = "Initial password for ad_bind_dn. Read once; Vault rotates it afterwards."
  type        = string
  default     = "/var/lib/vault-bootstrap/ad-bind-password"
}

variable "ad_ca_file" {
  description = "CA that signed the domain controller's LDAPS certificate."
  type        = string
  default     = "/var/lib/step-ca/root_ca.crt"
}

variable "ad_rotated_accounts" {
  description = "sAMAccountName => DN for each AD account Vault rotates."
  type        = map(string)
  default     = {}
}

variable "ad_consumers" {
  description = "Container name => the rotated account it may read."
  type        = map(string)
  default     = {}
}

variable "ad_rotation_seconds" {
  type    = number
  default = 86400 # daily
}

# --- OIDC login via Keycloak -------------------------------------------------

variable "enable_oidc" {
  description = "Set by vault-bootstrap once Keycloak's discovery endpoint answers."
  type        = bool
  default     = false
}

variable "oidc_issuer" {
  type    = string
  default = "https://idp01.lab.internal/realms/lab"
}

variable "oidc_client_id" {
  type    = string
  default = "vault"
}

variable "oidc_client_secret" {
  description = "Generated on hv01 and shared with Keycloak (write-only)."
  type        = string
  sensitive   = true
  ephemeral   = true
  default     = null
}

variable "oidc_policies" {
  description = "Policy name => HCL. Referenced by oidc_group_policies."
  type        = map(string)
  default     = {}
}

variable "oidc_group_policies" {
  description = "Department (groups claim value) => Vault policies."
  type        = map(list(string))
  default     = {}
}

# --- pam-reviewer credential (AppRoles bound to these addresses) -----------

variable "ai01_ip" {
  type    = string
  default = "192.168.100.19"
}

variable "hb01_ip" {
  type    = string
  default = "192.168.100.18"
}

# --- Ops agent (non-human identity) -----------------------------------------

variable "enable_agent" {
  description = "Vault owns the agent's AD password (needs the AD account from midPoint and svc-vault rights on its OU)."
  type        = bool
  default     = false
}

variable "agent_account" {
  type    = string
  default = "svc-agent-ops"
}

variable "agent_account_dn" {
  type    = string
  default = "CN=svc-agent-ops,OU=AI Agents,DC=ad,DC=lab,DC=internal"
}

variable "agent_rotation_seconds" {
  type    = number
  default = 43200 # 12 hours
}

# --- pam-review (ai01) as a governed non-human identity ----------------------

variable "enable_pam_review_agent" {
  description = "pam-review logs in as svc-pam-review (needs its AD account from midPoint). Set from hosts/lab/features.nix (pamReviewNhi) via features.auto.tfvars.json; retires the pam-reviewer KV secret and AppRoles."
  type        = bool
  default     = false
}

variable "pam_review_account" {
  type    = string
  default = "svc-pam-review"
}

variable "pam_review_account_dn" {
  type    = string
  default = "CN=svc-pam-review,OU=AI Agents,DC=ad,DC=lab,DC=internal"
}
