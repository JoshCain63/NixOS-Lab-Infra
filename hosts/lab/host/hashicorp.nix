# Host side of Vault (hv01) and Boundary (hb01).
{ config, pkgs, lib, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
  drive = "/mnt/wd_blue/containers";
  rootCa = "/var/lib/step-ca/certs/root_ca.crt";

  vaultTf    = ../../../terraform/vault;
  boundaryTf = ../../../terraform/boundary;
  keycloakTf = ../../../terraform/keycloak;
  targetsJson = pkgs.writeText "targets.auto.tfvars.json"
    (builtins.toJSON { linux_targets = import ../targets.nix; });
  # Feature switches Terraform must agree with the containers on.
  featuresJson = pkgs.writeText "features.auto.tfvars.json"
    (builtins.toJSON { enable_pam_review_agent = (import ../features.nix).pamReviewNhi; });

  afterSync = {
    wants = [ "lab-terraform-sync.service" ];
    after = [ "lab-terraform-sync.service" ];
  };
in
{
  # Client tools. BOUNDARY_*/VAULT_* point the CLIs at the lab and its CA.
  environment.systemPackages = [
    hc.boundary
    hc.vault
    pkgs.sshpass
    # Same exporter hb01 runs on a timer; uses BOUNDARY_ADDR/BOUNDARY_CACERT.
    (pkgs.writeShellScriptBin "boundary-risk-export" ''
      exec ${pkgs.python3}/bin/python3 ${../../../scripts}/boundary_risk_export.py "$@"
    '')
  ];
  environment.variables = {
    VAULT_ADDR      = "https://hv01.lab.internal";
    VAULT_CACERT    = rootCa;
    BOUNDARY_ADDR   = "https://hb01.lab.internal";
    BOUNDARY_CACERT = rootCa;
  };

  # Copy the Terraform from this flake onto the drive, where hv01/hb01
  # bind-mount it read-only. Re-runs whenever the Terraform changes.
  systemd.services.lab-terraform-sync = {
    description = "Sync lab Terraform onto the wd_blue drive";
    wantedBy = [ "multi-user.target" ];
    before = [ "container@hv01.service" "container@hb01.service" ];
    restartTriggers = [ vaultTf boundaryTf keycloakTf targetsJson featuresJson ];
    unitConfig.RequiresMountsFor = [ "/mnt/wd_blue" ];
    path = [ pkgs.rsync pkgs.coreutils ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      # sync_tf <source> <dest> [with-targets]
      sync_tf() {
        install -d -m 0755 "$2"
        rsync -r --delete --chmod=D755,F644 "$1/" "$2/"
        if [ "''${3:-}" = with-targets ]; then
          install -m 0644 ${targetsJson} "$2/targets.auto.tfvars.json"
          install -m 0644 ${featuresJson} "$2/features.auto.tfvars.json"
        fi
      }
      sync_tf ${vaultTf}    ${drive}/hv01/terraform with-targets
      sync_tf ${boundaryTf} ${drive}/hb01/terraform with-targets
      sync_tf ${keycloakTf} ${drive}/idp01/terraform

      # State directories (private to root on the host).
      install -d -m 0755 ${drive}/hb01/export ${drive}/hb01/events \
        ${drive}/ai01/ollama ${drive}/ai01/pam-review \
        ${drive}/wz01/wazuh ${drive}/wz01/containers \
        ${drive}/handoff/targets ${drive}/ag01 ${drive}/ag01/state
      # Agent queues: operators on the host (group agentq) and ag01 share them.
      install -d -m 2770 -g 2777 ${drive}/ag01/tasks ${drive}/ag01/proposals ${drive}/ag01/approvals
      install -d -m 0700 ${drive}/hv01/data ${drive}/hv01/bootstrap \
        ${drive}/hb01/boundary ${drive}/hb01/postgresql ${drive}/idp01/terraform-state \
        ${drive}/handoff ${drive}/handoff/hb01 ${drive}/handoff/idp01 ${drive}/handoff/mp01 \
        ${drive}/handoff/ai01 ${drive}/handoff/wz01 ${drive}/handoff/ag01
    '';
  };

  # These containers bind-mount directories the sync service creates.
  systemd.services."container@hv01"  = afterSync;
  systemd.services."container@hb01"  = afterSync;
  systemd.services."container@idp01" = afterSync;
  systemd.services."container@mp01"  = afterSync;
  systemd.services."container@ai01"  = afterSync;
  systemd.services."container@wz01"  = afterSync;
  systemd.services."container@ag01"  = afterSync;
  # Targets mount handoff/targets (approval public keys).
  systemd.services."container@lt01"  = afterSync;
  systemd.services."container@lt02"  = afterSync;
  systemd.services."container@lt03"  = afterSync;
  systemd.services."container@lt04"  = afterSync;
  systemd.services."container@lt05"  = afterSync;

  # The Wazuh indexer (OpenSearch) wants this; containers can't set it.
  boot.kernel.sysctl."vm.max_map_count" = 262144;
}
