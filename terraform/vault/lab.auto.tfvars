# AD password rotation. Check these DNs against your domain, complete the
# steps in docs/vault-boundary.md, then set enable_ad_rotation = true.
enable_ad_rotation = false

ad_bind_dn = "CN=svc-vault,CN=Users,DC=ad,DC=lab,DC=internal"
ad_user_dn = "DC=ad,DC=lab,DC=internal"

ad_rotated_accounts = {
  "svc-keycloak" = "CN=svc-keycloak,CN=Users,DC=ad,DC=lab,DC=internal"
  "svc-midpoint" = "CN=svc-midpoint,CN=Users,DC=ad,DC=lab,DC=internal"
}

ad_consumers = {
  idp01 = "svc-keycloak"
  mp01  = "svc-midpoint"
}

# OIDC login (Keycloak). Department => policies; departments not listed get
# only Vault's "default" policy (look up and renew their own token).
oidc_policies = {
  "lab-admin"    = <<-EOT
    path "*" { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }
  EOT
  "lab-readonly" = <<-EOT
    path "sys/mounts"         { capabilities = ["read"] }
    path "sys/policies/acl/*" { capabilities = ["read", "list"] }
    path "ssh-otp/roles/*"    { capabilities = ["read", "list"] }
    path "transit/keys/*"     { capabilities = ["read", "list"] }
  EOT
}

oidc_group_policies = {
  IT          = ["lab-admin", "agent-approver"]
  Engineering = ["lab-readonly"]
}

# Ops agent: set true once midPoint has created svc-agent-ops in OU=AI Agents
# and svc-vault can reset passwords there (docs/ops-agent.md).
enable_agent = true
