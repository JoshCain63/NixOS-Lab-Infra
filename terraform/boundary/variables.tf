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

  validation {
    condition     = alltrue([for t in values(var.linux_targets) : t.risk >= 1 && t.risk <= 5 && floor(t.risk) == t.risk])
    error_message = "Each target's risk must be a whole number from 1 to 5."
  }
}

variable "boundary_addr" {
  description = "Boundary API as seen from inside hb01."
  type        = string
  default     = "http://127.0.0.1:9200"
}

variable "vault_addr" {
  type    = string
  default = "https://hv01.lab.internal"
}

variable "ca_cert_file" {
  type    = string
  default = "/var/lib/step-ca/root_ca.crt"
}

variable "kms_token" {
  description = "Vault token for the transit keys (hand-off from hv01)."
  type        = string
  sensitive   = true
}

variable "credstore_token" {
  description = "Vault token for Boundary's credential store (hand-off from hv01)."
  type        = string
  sensitive   = true
}

variable "admin_password" {
  description = "Password for the Boundary admin login (generated on hb01)."
  type        = string
  sensitive   = true
}

variable "exporter_password" {
  description = "Password for the read-only risk-exporter login (generated on hb01)."
  type        = string
  sensitive   = true
}

variable "reviewer_password" {
  description = "Initial password for pam-reviewer (generated on hb01; rotated into Vault afterwards)."
  type        = string
  sensitive   = true
}

variable "public_addr" {
  description = "Boundary's public API address (used for OIDC callbacks)."
  type        = string
  default     = "https://hb01.lab.internal"
}

variable "enable_oidc" {
  description = "Set by boundary-terraform once Keycloak's discovery endpoint answers."
  type        = bool
  default     = false
}

variable "oidc_issuer" {
  type    = string
  default = "https://idp01.lab.internal/realms/lab"
}

variable "oidc_client_secret" {
  description = "Client secret for the Keycloak \"boundary\" client (from hv01)."
  type        = string
  sensitive   = true
  default     = ""
}

# --- Ops agent (non-human identity) -----------------------------------------

variable "enable_agent" {
  description = "Register the ops agent (needs its AD account from midPoint first)."
  type        = bool
  default     = false
}

variable "agent_account" {
  type    = string
  default = "svc-agent-ops"
}

variable "ad_url" {
  type    = string
  default = "ldaps://win-srv01.ad.lab.internal"
}

variable "ad_upn_domain" {
  description = "Domain for user@domain binds (the AD domain's UPN suffix)."
  type        = string
  default     = "ad.lab.internal"
}

variable "agent_user_dn" {
  type    = string
  default = "OU=AI Agents,DC=ad,DC=lab,DC=internal"
}

# --- pam-review (ai01) as a governed non-human identity ----------------------

variable "enable_pam_review_agent" {
  description = "pam-review logs in as svc-pam-review via LDAP and the local pam-reviewer account is removed. Set from hosts/lab/features.nix (pamReviewNhi) via features.auto.tfvars.json."
  type        = bool
  default     = false
}

variable "pam_review_account" {
  type    = string
  default = "svc-pam-review"
}
