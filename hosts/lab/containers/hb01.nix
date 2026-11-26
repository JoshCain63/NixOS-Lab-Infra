# hb01 — HashiCorp Boundary (Community Edition), controller + worker in one.
#
# - KMS keys (root, worker-auth, recovery) live in Vault's transit engine on
#   hv01 and rotate automatically there; nothing key-like is stored here.
# - The database is local PostgreSQL over the unix socket with peer auth, so
#   there is no DB password to manage at all.
# - Caddy terminates TLS for the API at https://hb01.lab.internal; the worker
#   proxy (9202) and cluster (9201) listeners use Boundary's own TLS.
# - boundary-terraform applies /etc/lab/terraform (synced from this repo onto
#   the wd_blue drive) using the recovery KMS, so no bootstrap admin is needed.
# - Its state-changing events also go straight to Wazuh (wz01), independent
#   of ai01. Until pam-review moves to its governed identity
#   (features.pamReviewNhi), it rotates the legacy pam-reviewer password into
#   Vault daily.
{ config, pkgs, lib, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
  handoff = "/var/lib/handoff";
  rootCa = "/var/lib/step-ca/root_ca.crt";

  kms = purpose: key: ''
    kms "transit" {
      purpose     = "${purpose}"
      address     = "https://hv01.lab.internal"
      key_name    = "${key}"
      mount_path  = "transit/"
      tls_ca_cert = "${rootCa}"
    }
  '';

  # The transit token comes from VAULT_TOKEN in /run/boundary/env.
  configFile = pkgs.writeText "boundary.hcl" ''
    disable_mlock = true

    controller {
      name                = "hb01-controller"
      public_cluster_addr = "hb01.lab.internal:9201"
      database {
        url = "postgresql:///boundary?host=/run/postgresql"
      }
    }

    worker {
      name        = "hb01-worker"
      public_addr = "hb01.lab.internal:9202"
      # No initial_upstreams: this is a combined controller+worker, and
      # Boundary 0.21.3 refuses to start if the key is present with anything
      # other than the controller's own cluster address. The worker attaches
      # to the in-process controller on its own.
    }

    listener "tcp" {
      purpose     = "api"
      address     = "127.0.0.1:9200"
      tls_disable = true
    }
    listener "tcp" {
      purpose = "cluster"
      address = "0.0.0.0:9201"
    }
    listener "tcp" {
      purpose = "proxy"
      address = "0.0.0.0:9202"
    }
    listener "tcp" {
      purpose     = "ops"
      address     = "127.0.0.1:9203"
      tls_disable = true
    }

    # Audit trail. The PAM reviewer on ai01 reads sessions from the API; this
    # file is the raw record, mounted read-only into ai01.
    events {
      audit_enabled        = true
      observations_enabled = true
      sysevents_enabled    = true

      sink "stderr" {
        name        = "stderr"
        event_types = ["error", "system"]
        format      = "hclog-text"
      }

      sink {
        name        = "file"
        description = "Audit and observation events"
        event_types = ["audit", "observation", "error"]
        format      = "cloudevents-json"
        file {
          path             = "/var/lib/boundary-events"
          file_name        = "events.ndjson"
          rotate_duration  = "24h"
          rotate_max_files = 30
        }
      }

      # Wazuh feed (forwarded to wz01 by rsyslog): state-changing requests
      # only. Reads (GET), e.g. pam-review polling sessions, are dropped so
      # the SOC sees logins, session authorizations, cancels and IAM changes.
      sink {
        name         = "wazuh"
        description  = "State-changing events for Wazuh on wz01"
        event_types  = ["audit", "observation", "error"]
        format       = "cloudevents-json"
        deny_filters = ["\"/data/request_info/method\" contains \"GET\""]
        file {
          path             = "/var/lib/boundary-events"
          file_name        = "wazuh.ndjson"
          rotate_duration  = "24h"
          rotate_max_files = 7
        }
      }
    }

    ${kms "root" "boundary-root"}
    ${kms "worker-auth" "boundary-worker-auth"}
    ${kms "recovery" "boundary-recovery"}
  '';

  boundary = "${hc.boundary}/bin/boundary";

  # Recovery KMS for the rotation job (token comes from VAULT_TOKEN).
  recoveryHcl = pkgs.writeText "recovery.hcl" ''
    kms "transit" {
      purpose         = "recovery"
      address         = "https://hv01.lab.internal"
      key_name        = "boundary-recovery"
      mount_path      = "transit/"
      tls_ca_cert     = "${rootCa}"
      disable_renewal = "true"
    }
  '';
in
{
  # Boundary's write events -> Wazuh, straight from here (see the "wazuh" sink).
  #
  # Glob, not the literal "wazuh.ndjson": because the sink below sets
  # rotate_duration, Boundary's eventlogger inserts a nanosecond timestamp
  # before the extension, so what actually lands on disk is
  #   wazuh-1795490437911356475.ndjson
  # and the literal name is never created. rsyslog said so plainly on every
  # start - "imfile: on startup file '/var/lib/boundary-events/wazuh.ndjson'
  # does not exist but is configured in static file monitor" - and Boundary's
  # independent event stream therefore never reached Wazuh, so rules
  # 100200-100209 could not fire. A glob also follows the file across each
  # rotation, which a static monitor would not.
  imports = [
    (import ./wazuh-forward.nix { file = "/var/lib/boundary-events/wazuh-*.ndjson"; tag = "boundary"; })
  ];

  networking.hostName = "hb01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];
  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 80 443 9201 9202 ];
  system.stateVersion = "26.05";

  environment.systemPackages = [ hc.boundary ];

  users.users.boundary = {
    isSystemUser = true;
    group = "boundary";
    home = "/var/lib/boundary";
  };
  users.groups.boundary = {};

  services.postgresql = {
    enable = true;
    ensureDatabases = [ "boundary" ];
    ensureUsers = [{ name = "boundary"; ensureDBOwnership = true; }];
  };

  services.caddy = {
    enable = true;
    virtualHosts."hb01.lab.internal".extraConfig = ''
      tls {
        ca https://pki.lab.internal:9000/acme/acme/directory
        ca_root ${rootCa}
      }
      reverse_proxy 127.0.0.1:9200
    '';
  };
  systemd.services.caddy.serviceConfig = {
    ReadOnlyPaths = [ "/var/lib/step-ca" ];
    ProtectSystem = "false";
  };

  # Wait until Vault is up and hv01 has handed over valid tokens, then stage
  # the transit token for Boundary's KMS blocks.
  systemd.services.boundary-vault-wait = {
    description = "Wait for Vault and stage Boundary's KMS token";
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    path = [ pkgs.curl pkgs.coreutils ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
      TimeoutStartSec = "20min";
    };
    script = ''
      valid() {
        [ -s "$1" ] && curl -sf --cacert ${rootCa} -H "X-Vault-Token: $(cat "$1")" \
          https://hv01.lab.internal/v1/auth/token/lookup-self >/dev/null
      }
      until valid ${handoff}/kms-token && valid ${handoff}/credstore-token; do
        echo "Waiting for Vault on hv01 and its hand-off tokens..."
        sleep 10
      done
      mkdir -p /run/boundary
      printf 'VAULT_TOKEN=%s\n' "$(cat ${handoff}/kms-token)" > /run/boundary/env
    '';
  };

  systemd.services.boundary-db = {
    description = "Initialise or migrate the Boundary database";
    after    = [ "postgresql.service" "postgresql-setup.service" "boundary-vault-wait.service" ];
    requires = [ "postgresql.service" "boundary-vault-wait.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      User = "boundary";
      Group = "boundary";
      StateDirectory = "boundary";
      StateDirectoryMode = "0700";
      EnvironmentFile = "/run/boundary/env";
    };
    script = ''
      if [ -e /var/lib/boundary/.db-initialized ]; then
        ${boundary} database migrate -config ${configFile}
      else
        # Skip the generated admin/scopes/targets: Terraform creates them.
        ${boundary} database init -config ${configFile} \
          -skip-auth-method-creation -skip-host-resources-creation \
          -skip-scopes-creation -skip-target-creation
        touch /var/lib/boundary/.db-initialized
      fi
    '';
  };

  systemd.services.boundary = {
    description = "Boundary controller and worker";
    wantedBy = [ "multi-user.target" ];
    after    = [ "boundary-db.service" ];
    requires = [ "boundary-db.service" ];
    serviceConfig = {
      User = "boundary";
      Group = "boundary";
      EnvironmentFile = "/run/boundary/env";
      ExecStart = "${boundary} server -config ${configFile}";
      Restart = "on-failure";
      RestartSec = "10s";
      LimitNOFILE = 65536;
    };
  };

  systemd.services.boundary-terraform = {
    description = "Configure Boundary from Terraform";
    wantedBy = [ "multi-user.target" ];
    after    = [ "boundary.service" ];
    requires = [ "boundary.service" ];
    path = [ hc.terraform pkgs.curl pkgs.coreutils pkgs.findutils ];
    environment = {
      HOME = "/var/lib/boundary";
      CHECKPOINT_DISABLE = "1";
      TF_IN_AUTOMATION = "1";
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
    };
    script = ''
      set -uo pipefail
      for _ in $(seq 1 60); do
        curl -sf http://127.0.0.1:9203/health >/dev/null && break
        sleep 5
      done

      S=/var/lib/boundary
      # Passwords for the local logins, generated once.
      for f in admin-password exporter-password reviewer-initial-password; do
        if [ ! -s $S/$f ]; then
          head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 24 > $S/$f
        fi
      done

      export TF_VAR_kms_token="$(cat ${handoff}/kms-token)"
      export TF_VAR_credstore_token="$(cat ${handoff}/credstore-token)"
      export TF_VAR_admin_password="$(cat $S/admin-password)"
      export TF_VAR_exporter_password="$(cat $S/exporter-password)"
      # pam-reviewer's first password only; pam-reviewer-rotate replaces it
      # straight away and keeps it in Vault from then on.
      export TF_VAR_reviewer_password="$(cat $S/reviewer-initial-password)"

      # OIDC (Keycloak) login: needs the client secret from hv01, and
      # Boundary validates the issuer's discovery document when it's created.
      oidc=false
      if [ -s ${handoff}/boundary-oidc-secret ]; then
        export TF_VAR_oidc_client_secret="$(cat ${handoff}/boundary-oidc-secret)"
        for _ in $(seq 1 30); do
          if curl -sf --cacert ${rootCa} https://idp01.lab.internal/realms/lab/.well-known/openid-configuration >/dev/null; then
            oidc=true; break
          fi
          sleep 10
        done
      fi
      export TF_VAR_enable_oidc=$oidc
      if [ $oidc = true ]; then rm -f $S/.oidc-pending; else
        echo "Keycloak not reachable yet; OIDC login will be configured on a later run"
        touch $S/.oidc-pending
      fi

      W=$S/terraform
      mkdir -p $W
      find $W -maxdepth 1 \( -name '*.tf' -o -name '*.tfvars' -o -name '*.tfvars.json' \) -delete
      cp --no-preserve=mode /etc/lab/terraform/* $W/
      terraform -chdir=$W init -input=false -plugin-dir=${hc.terraformPlugins}
      terraform -chdir=$W apply -input=false -auto-approve

      # Publish the agent LDAP auth method id for ai01 and ag01, which mount
      # /var/lib/boundary-export read-only. Boundary doesn't list LDAP auth
      # methods to the anonymous principal, so the agents can't discover it;
      # authenticating by id works, they just need to be told the id. 0644
      # because the readers run as their own service users, and an auth method
      # id is not a secret.
      amid=$(terraform -chdir=$W output -raw agent_auth_method_id 2>/dev/null || true)
      f=/var/lib/boundary-export/agent-auth-method-id
      if [ -n "$amid" ]; then
        printf '%s' "$amid" > $f.tmp && chmod 0644 $f.tmp && mv $f.tmp $f
      else
        rm -f $f
      fi
    '';
  };

  # Export every target's risk factor to JSON (scripts/boundary_risk_export.py).
  # Output: /var/lib/boundary-export/target-risk.json, which is
  # /mnt/wd_blue/containers/hb01/export/target-risk.json on the host.
  systemd.tmpfiles.rules = [
    "d /var/lib/boundary-export 0755 boundary boundary -"
    "d /var/lib/boundary-events 0750 boundary boundary -"
  ];

  # Re-run Terraform while OIDC login is still waiting on Keycloak.
  systemd.services.boundary-oidc-retry = {
    description = "Retry Boundary OIDC setup";
    unitConfig.ConditionPathExists = "/var/lib/boundary/.oidc-pending";
    serviceConfig.Type = "oneshot";
    script = "${pkgs.systemd}/bin/systemctl restart boundary-terraform.service";
  };
  systemd.timers.boundary-oidc-retry = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "15min"; OnUnitActiveSec = "15min"; };
  };

  systemd.services.boundary-risk-export = {
    description = "Export Boundary target risk factors to JSON";
    after    = [ "boundary-terraform.service" ];
    requires = [ "boundary-terraform.service" ];
    serviceConfig = {
      Type = "oneshot";
      User = "boundary";
      Group = "boundary";
      LoadCredential = "password:/var/lib/boundary/exporter-password";
      ExecStart = lib.concatStringsSep " " [
        "${pkgs.python3}/bin/python3 ${../../../scripts}/boundary_risk_export.py"
        "--addr http://127.0.0.1:9200"
        "--output /var/lib/boundary-export/target-risk.json"
      ];
      # Exit code 2 = exported, but some target had no valid risk.
      SuccessExitStatus = [ 2 ];
    };
  };
  systemd.timers.boundary-risk-export = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "5min"; OnUnitActiveSec = "5min"; };
  };

  # LEGACY pam-reviewer credential: new password daily (and at boot), set on
  # the Boundary account via the recovery KMS, then stored in Vault KV
  # (secret/boundary/pam-reviewer) for ai01. Retired, and skipped, once
  # features.pamReviewNhi is on: hv01 withdraws hb01's AppRole hand-off. hb01's AppRole may only write
  # that path, from this address, with 5-minute tokens.
  systemd.services.pam-reviewer-rotate = {
    description = "Rotate the pam-reviewer Boundary password into Vault";
    wantedBy = [ "multi-user.target" ];
    after    = [ "boundary-terraform.service" ];
    requires = [ "boundary-terraform.service" ];
    path = [ hc.boundary hc.terraform pkgs.curl pkgs.jq pkgs.coreutils ];
    environment = { HOME = "/var/lib/boundary"; CHECKPOINT_DISABLE = "1"; };
    unitConfig.ConditionPathExists = "${handoff}/role_id";
    serviceConfig = {
      Type = "oneshot";
      UMask = "0077";
      EnvironmentFile = "/run/boundary/env"; # VAULT_TOKEN for the recovery KMS
    };
    script = ''
      set -euo pipefail
      V=https://hv01.lab.internal
      vcurl() { curl -sf --cacert ${rootCa} "$@"; }

      id=$(terraform -chdir=/var/lib/boundary/terraform output -raw pam_reviewer_account_id)
      if [ -z "$id" ]; then
        # pam-review logs in as its governed identity (svc-pam-review, password
        # owned by Vault's LDAP engine); the local account is gone.
        echo "pam-reviewer retired (features.pamReviewNhi); nothing to rotate"; exit 0
      fi

      login=$(jq -n --rawfile r ${handoff}/role_id --rawfile s ${handoff}/secret_id \
        '{role_id: ($r | rtrimstr("\n")), secret_id: ($s | rtrimstr("\n"))}')
      vtoken=$(vcurl -X POST $V/v1/auth/approle/login -d "$login" | jq -r .auth.client_token)
      trap 'vcurl -H "X-Vault-Token: $vtoken" -X POST $V/v1/auth/token/revoke-self >/dev/null || true' EXIT

      NEW_PW=$(head -c 48 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32)
      export NEW_PW
      boundary accounts set-password -id "$id" -password env://NEW_PW \
        -recovery-config ${recoveryHcl} -addr http://127.0.0.1:9200 -format json >/dev/null

      body=$(jq -n --arg p "$NEW_PW" --arg id "$id" \
        '{data: {login_name: "pam-reviewer", password: $p, account_id: $id, rotated_at: (now | todate)}}')
      for _ in 1 2 3 4 5; do
        if vcurl -H "X-Vault-Token: $vtoken" -X POST $V/v1/secret/data/boundary/pam-reviewer -d "$body" >/dev/null; then
          echo "pam-reviewer password rotated"; exit 0
        fi
        sleep 5
      done
      echo "Boundary password changed but the Vault write failed; ai01 is locked out until the next rotation" >&2
      exit 1
    '';
  };
  systemd.timers.pam-reviewer-rotate = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnCalendar = "daily"; Persistent = true; RandomizedDelaySec = "30min"; };
  };
}
