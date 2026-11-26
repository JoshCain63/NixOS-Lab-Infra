# ag01 — the ops agent: an AI non-human identity running named tools.
#
# For each task it gets a Keycloak workload token, exchanges it in Vault for
# its AD password (Vault rotates it; midPoint governs the account's lifecycle),
# logs in to Boundary via LDAP, and calls named tools on in-scope targets, one
# Boundary session per call. The targets' agent gate decides what runs.
# Model: Qwen2.5-3B on ai01's Ollama (port open only to this container).
# Everything it does goes to an append-only ledger -> pam-review + Wazuh.
# See docs/ops-agent.md.
{ config, pkgs, lib, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
  targets = import ../targets.nix;
  scripts = ../../../scripts;
  S = "/var/lib/ops-agent";

  agentEnv = {
    PYTHONPATH = "${scripts}";
    PYTHONDONTWRITEBYTECODE = "1";
  };
  agentPath = [ hc.boundary pkgs.sshpass pkgs.openssh pkgs.coreutils ];
in
{
  networking.hostName = "ag01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];
  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ ]; # nothing listens here
  system.stateVersion = "26.05";

  environment.systemPackages = [ hc.boundary pkgs.sshpass ];

  # Fixed gid shared with the host, so `agent-task` / `agent-approvals` (run by
  # an operator on the host) can drop files in the queue folders.
  users.groups.agentq.gid = 2777;
  users.users.ops-agent = {
    isSystemUser = true;
    group = "ops-agent";
    extraGroups = [ "agentq" ];
    home = S;
  };
  users.groups.ops-agent = {};

  systemd.tmpfiles.rules = [ "d ${S}/state 0755 ops-agent ops-agent -" ];

  environment.etc."ops-agent.json".text = builtins.toJSON {
    keycloak_token_url = "https://idp01.lab.internal/realms/lab/protocol/openid-connect/token";
    client_id = "ops-agent";
    vault_addr = "https://hv01.lab.internal";
    vault_jwt_path = "jwt-keycloak";
    vault_role = "ops-agent";
    account = "svc-agent-ops";
    boundary_addr = "https://hb01.lab.internal";
    # Boundary hides LDAP auth methods from the anonymous auth-method list, so
    # the id can't be discovered; hb01 publishes it here from its Terraform
    # output.
    auth_method_id_file = "/var/lib/boundary-export/agent-auth-method-id";
    target_scope = "linux-targets";
    ca_file = "/var/lib/step-ca/root_ca.crt";
    ollama_url = "http://ai01.lab.internal:11434";
    model = "lab-qwen2.5-3b";
    ledger = "${S}/state/ledger.ndjson";
    tasks_dir = "${S}/tasks";
    proposals_dir = "${S}/proposals";
    approvals_dir = "${S}/approvals";
    approval_timeout = 1800;
    sweep_hosts = builtins.attrNames (lib.filterAttrs (_: t: t.agent_scope) targets);
  };

  # Ledger -> Wazuh (independent of what pam-review makes of it).
  imports = [ (import ./wazuh-forward.nix { file = "${S}/state/ledger.ndjson"; tag = "ops-agent"; }) ];

  # Run queued tasks. Triggered whenever a task file appears.
  systemd.services.ops-agent = {
    description = "Ops agent: run queued tasks";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    environment = agentEnv;
    path = agentPath;
    unitConfig.ConditionPathExists = "/var/lib/handoff/ops-agent-oidc-secret";
    serviceConfig = {
      Type = "oneshot";
      User = "ops-agent";
      Group = "ops-agent";
      SupplementaryGroups = [ "agentq" ];
      # Its Keycloak client secret; everything else is fetched per task.
      LoadCredential = "client_secret:/var/lib/handoff/ops-agent-oidc-secret";
      ExecStart = "${pkgs.python3}/bin/python3 -m ops_agent run-queue";
      TimeoutStartSec = "2h"; # includes waiting for human approvals
      UMask = "0022";
      NoNewPrivileges = true;
      CapabilityBoundingSet = "";
      ProtectSystem = "strict";
      ReadWritePaths = [ S ];
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryMax = "512M";
    };
  };
  systemd.paths.ops-agent = {
    wantedBy = [ "multi-user.target" ];
    pathConfig.PathExistsGlob = "${S}/tasks/*.json";
  };

  # Scheduled Tier 0 health sweep of the in-scope hosts (queues one task each).
  systemd.services.ops-agent-sweep = {
    description = "Ops agent: queue a health sweep";
    environment = agentEnv;
    serviceConfig = {
      Type = "oneshot";
      User = "ops-agent";
      Group = "ops-agent";
      SupplementaryGroups = [ "agentq" ];
      UMask = "0002";
      ExecStart = "${pkgs.python3}/bin/python3 -m ops_agent sweep";
    };
  };
  systemd.timers.ops-agent-sweep = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "30min"; OnUnitActiveSec = "6h"; };
  };
}
