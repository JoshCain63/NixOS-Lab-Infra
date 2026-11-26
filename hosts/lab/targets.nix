# Linux targets reachable through Boundary. Single source of truth: this list
# drives the containers, DNS records, the Vault OTP role and Boundary targets.
#
# risk:   1 (lowest) to 5 (highest), based on the sensitivity of what the
#         host holds. Boundary carries it in each target's description, and
#         scripts/boundary_risk_export.py exports it as JSON.
# owners: departments (AD "department", the Keycloak "groups" claim) that
#         normally use the host. Anyone else connecting raises the risk score.
# access: departments Boundary lets connect. Deliberately wider than owners
#         in places, so allowed-but-unusual sessions happen and get reviewed.
# agent_scope: whether the ops agent (ag01) may run its named tools here.
#         lt05 (finance) is out of scope: Boundary denies the agent there.
{
  lt01 = {
    ip     = "192.168.100.31";
    risk   = 1;
    tier   = "low";
    role   = "General-purpose workstation";
    data   = "public";
    owners = [ "Engineering" "IT" "HR" "Finance" "Operations" ];
    access = [ "Engineering" "IT" "HR" "Finance" "Operations" ];
    agent_scope = true;
  };
  lt02 = {
    ip     = "192.168.100.32";
    risk   = 2;
    tier   = "guarded";
    role   = "Developer workstation";
    data   = "internal";
    owners = [ "Engineering" ];
    access = [ "Engineering" "IT" ];
    agent_scope = true;
  };
  lt03 = {
    ip     = "192.168.100.33";
    risk   = 3;
    tier   = "elevated";
    role   = "Internal application server";
    data   = "internal";
    owners = [ "Engineering" "Operations" ];
    access = [ "Engineering" "Operations" "IT" ];
    agent_scope = true;
  };
  lt04 = {
    ip     = "192.168.100.34";
    risk   = 4;
    tier   = "high";
    role   = "HR file server";
    data   = "confidential (employee PII)";
    owners = [ "HR" ];
    access = [ "HR" "IT" ];
    agent_scope = true;
  };
  lt05 = {
    ip     = "192.168.100.35";
    risk   = 5;
    tier   = "critical";
    role   = "Finance database host";
    data   = "restricted (financial records, credentials)";
    owners = [ "Finance" ];
    access = [ "Finance" "IT" "Engineering" ];
    agent_scope = false;
  };
}
