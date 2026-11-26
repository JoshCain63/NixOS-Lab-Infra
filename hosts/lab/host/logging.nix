{ config, pkgs, ... }:

# Enforces the lab's 48h log retention requirement from the host side.
# Vault's audit log (hv01) and Boundary's audit event log (hb01) are each
# bind-mounted out to these host paths (see containers.nix) specifically
# so a single host-level logrotate policy can own retention for both,
# rather than reimplementing rotation/retention logic inside two
# different container images.
#
# Both logs are already deliberately narrow — Vault's audit device logs
# request/response metadata for the ssh-client-signer engine only, and
# Boundary's event sink only emits `audit` events (see hb01.nix) — so
# volume stays low enough for the local Qwen2.5-3B grader (ai01) to
# consume directly without needing log shipping or an intermediate index.

{
  services.logrotate.enable = true;

  services.logrotate.settings = {
    "/var/log/lab/vault-audit/*.json" = {
      frequency   = "hourly";
      rotate      = 2;      # 2 x 24h rotations retained = 48h max
      maxage      = 2;
      compress    = true;
      missingok   = true;
      notifempty  = true;
      su          = "root root";
    };

    "/var/log/lab/boundary/*.ndjson" = {
      frequency   = "hourly";
      rotate      = 2;
      maxage      = 2;
      compress    = true;
      missingok   = true;
      notifempty  = true;
      su          = "root root";
    };
  };
}
