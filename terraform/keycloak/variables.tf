variable "keycloak_url" {
  description = "Keycloak as seen from inside idp01."
  type        = string
  default     = "http://127.0.0.1"
}

variable "admin_username" {
  type    = string
  default = "admin"
}

variable "admin_password" {
  type      = string
  sensitive = true
}

variable "secrets_dir" {
  description = "Hand-off directory with <client>-oidc-secret files from hv01."
  type        = string
  default     = "/var/lib/handoff"
}

variable "department_attribute" {
  description = "Keycloak user attribute holding the AD department (set by the LDAP federation mapper)."
  type        = string
  default     = "department"
}
