# hv01 — HashiCorp Vault.
#
# Vault listens on localhost only; Caddy terminates TLS for
# https://hv01.lab.internal with a cert from step-ca (same pattern as svc01).
#
# On every boot vault-bootstrap:
#   1. initialises Vault the first time (1 unseal key, lab only),
#   2. unseals it,
#   3. applies the Terraform in /etc/lab/terraform (synced from this repo onto
#      the wd_blue drive by the host),
#   4. hands short-lived, auto-renewing tokens / AppRole IDs to the other
#      containers through /var/lib/handoff/<container>/.
#
# Vault's audit log (/var/log/vault/audit.log) is forwarded to Wazuh.
#
# LAB ONLY: the unseal key and root token live in
# /var/lib/vault-bootstrap/init.json on the same drive as the Vault data.
{ config, pkgs, lib, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
  bootstrapDir = "/var/lib/vault-bootstrap";
  handoff = "/var/lib/handoff";
  auditLog = "/var/log/vault/audit.log"; # = audit_log_path in terraform/vault

  common = ''
    set -uo pipefail
    export VAULT_ADDR=http://127.0.0.1:8200
    B=${bootstrapDir}

    # vault status exits 0 = unsealed, 2 = sealed, 1 = unreachable
    status() { vault status -format=json 2>/dev/null || true; }

    wait_for_vault() {
      for _ in $(seq 1 60); do
        [ -n "$(status)" ] && return 0
        sleep 2
      done
      echo "Vault never came up" >&2
      return 1
    }

    unseal() {
      if [ "$(status | jq -r .sealed)" = "true" ]; then
        vault operator unseal "$(jq -r '.unseal_keys_b64[0]' $B/init.json)" >/dev/null
        echo "Vault unsealed"
      fi
    }
  '';
in
{
  networking.hostName = "hv01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];
  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 80 443 ];
  system.stateVersion = "26.05";

  environment.systemPackages = [ hc.vault ];
  environment.variables.VAULT_ADDR = "http://127.0.0.1:8200";

  services.vault = {
    enable = true;
    package = hc.vault;
    address = "127.0.0.1:8200";
    storageBackend = "raft";
    storageConfig = ''
      node_id = "hv01"
    '';
    extraConfig = ''
      api_addr      = "https://hv01.lab.internal"
      cluster_addr  = "https://127.0.0.1:8201"
      disable_mlock = true
      ui            = true
    '';
  };

  # Audit log (the file device in terraform/vault): systemd creates
  # /var/log/vault owned by the vault user. Vault fails closed if it can't
  # write here, so this must exist before Terraform enables the device.
  systemd.services.vault.serviceConfig = {
    LogsDirectory = "vault";
    LogsDirectoryMode = "0700";
  };

  # Forward it to Wazuh (wz01), straight from here like Boundary's trail.
  imports = [
    (import ./wazuh-forward.nix { file = auditLog; tag = "vault"; })
  ];

  # Vault reopens its audit file on SIGHUP.
  services.logrotate = {
    enable = true;
    settings.${auditLog} = {
      frequency = "daily";
      rotate = 14;
      compress = true;
      delaycompress = true;
      missingok = true;
      notifempty = true;
      postrotate = "${pkgs.systemd}/bin/systemctl kill -s HUP --kill-whom=main vault.service";
    };
  };

  services.caddy = {
    enable = true;
    virtualHosts."hv01.lab.internal".extraConfig = ''
      tls {
        ca https://pki.lab.internal:9000/acme/acme/directory
        ca_root /var/lib/step-ca/root_ca.crt
      }
      reverse_proxy 127.0.0.1:8200
    '';
  };
  systemd.services.caddy.serviceConfig = {
    ReadOnlyPaths = [ "/var/lib/step-ca" ];
    ProtectSystem = "false";
  };

  systemd.services.vault-bootstrap = {
    description = "Initialise, unseal and configure Vault from Terraform";
    after    = [ "vault.service" ];
    requires = [ "vault.service" ];
    wantedBy = [ "multi-user.target" ];
    path = [ hc.vault hc.terraform pkgs.jq pkgs.coreutils pkgs.findutils pkgs.curl ];
    environment = {
      HOME = bootstrapDir;
      CHECKPOINT_DISABLE = "1";
      TF_IN_AUTOMATION = "1";
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
    };
    script = common + ''
      wait_for_vault

      if [ "$(status | jq -r .initialized)" != "true" ]; then
        echo "Initialising Vault (first boot)"
        vault operator init -key-shares=1 -key-threshold=1 -format=json > $B/init.json.tmp
        mv $B/init.json.tmp $B/init.json
      fi
      unseal

      export VAULT_TOKEN=$(jq -r .root_token $B/init.json)

      # Wait until this node is the raft leader and can take writes.
      for _ in $(seq 1 30); do
        vault read -format=json sys/leader 2>/dev/null | jq -e '.data.is_self' >/dev/null && break
        sleep 2
      done

      # --- Generated-once secrets handed to other containers ---
      # gen <name> <length> [suffix]: random alphanumerics (+ optional suffix,
      # used to satisfy Wazuh's API password policy: upper, lower, digit, symbol).
      gen() {
        [ -s $B/$1 ] || { head -c 96 /dev/urandom | base64 | tr -d '/+=\n' | head -c $2; printf '%s' "''${3:-}"; } > $B/$1
      }
      give() { mkdir -p ${handoff}/$2; install -m 0600 $B/$1 ${handoff}/$2/$1; }

      # OIDC client secrets: Keycloak (idp01) registers each client with its
      # secret; the consumer gets a copy.
      for c in boundary vault wazuh pam-report ops-agent pam-review; do
        gen $c-oidc-secret 40
        give $c-oidc-secret idp01
      done
      give ops-agent-oidc-secret ag01
      give pam-review-oidc-secret ai01   # pam-review's workload client (svc-pam-review)
      give boundary-oidc-secret hb01
      give wazuh-oidc-secret wz01
      give pam-report-oidc-secret ai01

      # oauth2-proxy cookie secret for ai01's report page. It is read with
      # cookie.secretFile, and oauth2-proxy uses the file's RAW bytes as the
      # AES key, so the file must be exactly 16, 24 or 32 bytes long. base64 of
      # 32 random bytes is 44 characters, which it rejects with
      #   cookie_secret from file must be 16, 24, or 32 bytes to create an AES
      #   cipher, but is 44 bytes
      # base64url of 24 random bytes is exactly 32 characters and needs no
      # padding, so it satisfies both the length rule and cookie-safe charset.
      [ -s $B/pam-report-cookie-secret ] || head -c 24 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > $B/pam-report-cookie-secret
      give pam-report-cookie-secret ai01

      # Wazuh (wz01): indexer admin (break-glass), dashboard service user, API user.
      gen wazuh-admin-password 28
      gen wazuh-kibanaserver-password 28
      gen wazuh-api-password 28 'Aa1.-'
      for f in wazuh-admin-password wazuh-kibanaserver-password wazuh-api-password; do give $f wz01; done

      # The pam-reviewer Boundary credential is NOT handed out here: it lives in
      # Vault (secret/boundary/pam-reviewer), rotated daily by hb01 and read by
      # ai01 with 5-minute AppRole tokens. See terraform/vault (pam-reviewer).
      export TF_VAR_oidc_client_secret="$(cat $B/vault-oidc-secret)"

      # Vault validates the issuer's discovery document when the OIDC method
      # is written, so only enable it once Keycloak answers over HTTPS.
      # Otherwise apply everything else and let vault-oidc-retry try again.
      discovery=https://idp01.lab.internal/realms/lab/.well-known/openid-configuration
      oidc=false
      for _ in $(seq 1 30); do
        if curl -sf --cacert /var/lib/step-ca/root_ca.crt $discovery >/dev/null; then
          oidc=true; break
        fi
        sleep 10
      done
      export TF_VAR_enable_oidc=$oidc
      if [ $oidc = true ]; then rm -f $B/.oidc-pending; else
        echo "Keycloak not reachable yet; OIDC login will be configured on a later run"
        touch $B/.oidc-pending
      fi

      # --- Terraform: copy the read-only source into a persistent workdir ---
      W=$B/terraform
      mkdir -p $W
      find $W -maxdepth 1 \( -name '*.tf' -o -name '*.tfvars' -o -name '*.tfvars.json' \) -delete
      cp --no-preserve=mode /etc/lab/terraform/* $W/
      terraform -chdir=$W init -input=false -plugin-dir=${hc.terraformPlugins}
      terraform -chdir=$W apply -input=false -auto-approve

      # --- Hand-offs to other containers ---
      # Tokens come from the token roles Terraform defines: orphan, periodic,
      # renewable. Boundary renews them itself; they're only re-issued here if
      # they expired (e.g. the lab was powered off for longer than the period).
      ensure_token() {
        local file=$1 role=$2
        if [ -s "$file" ] && VAULT_TOKEN=$(cat "$file") vault token lookup >/dev/null 2>&1; then
          return 0
        fi
        echo "Issuing new $role token"
        # Pass the period explicitly: Vault 2.2 doesn't apply the role's
        # token_period on its own, and Boundary rejects non-periodic tokens.
        local period
        period=$(vault read -field=token_period auth/token/roles/$role)
        vault token create -role="$role" -policy="$role" -period="''${period}s" -field=token > "$file.tmp"
        mv "$file.tmp" "$file"
      }
      mkdir -p ${handoff}/hb01
      ensure_token ${handoff}/hb01/kms-token boundary-kms
      ensure_token ${handoff}/hb01/credstore-token boundary-credstore

      # AppRoles exist only when AD rotation is enabled in Terraform.
      for role in $(vault list -format=json auth/approle/role 2>/dev/null | jq -r '.[]' || true); do
        d=${handoff}/$role
        mkdir -p $d
        vault read -field=role_id auth/approle/role/$role/role-id > $d/role_id
        if ! { [ -s $d/secret_id ] && vault write -format=json auth/approle/role/$role/secret-id/lookup \
                 secret_id="$(cat $d/secret_id)" 2>/dev/null | jq -e .data >/dev/null; }; then
          echo "Issuing new AppRole secret_id for $role"
          vault write -f -field=secret_id auth/approle/role/$role/secret-id > $d/secret_id
        fi
      done

      # Withdraw hand-offs for AppRoles Terraform has retired (ai01 and hb01's
      # pam-reviewer roles, once pam-review logs in as its governed identity),
      # so nothing keeps trying them. Exit 2 = no roles left at all; anything
      # else non-zero is an error, and then nothing is removed.
      # `; rc=$?` cannot work here: the script runs under `set -e`, so the
      # assignment itself aborts the script when vault exits non-zero and rc
      # is never read. `vault list` exits 2 on an empty path, and the path IS
      # empty once pamReviewNhi retires both pam-reviewer AppRoles - so this
      # killed vault-bootstrap (status=2/INVALIDARGUMENT) immediately after a
      # successful terraform apply, but only after the switch was flipped.
      rc=0
      approles=$(vault list -format=json auth/approle/role 2>/dev/null) || rc=$?
      if [ $rc -eq 0 ] || [ $rc -eq 2 ]; then
        [ $rc -eq 2 ] && approles='[]'
        for d in ${handoff}/*/; do
          role=$(basename "$d")
          [ -e "$d/role_id" ] || continue
          if ! echo "$approles" | jq -e --arg r "$role" 'index($r) != null' >/dev/null; then
            echo "AppRole $role retired; removing its hand-off"
            rm -f "$d/role_id" "$d/secret_id"
          fi
        done
      fi

      # Ops agent approvals: publish every version of the ed25519 public key
      # for the targets' agent gate (read-only mount there). Public, so 0644.
      mkdir -p ${handoff}/targets
      if vault read -format=json transit/keys/agent-approvals > $B/agent-approvals.json 2>/dev/null; then
        jq -r '.data.keys | to_entries[] | "\(.key) \(.value.public_key)"' $B/agent-approvals.json |
          while read -r version key; do
            printf '%s' "$key" > ${handoff}/targets/v$version.pub.tmp
            chmod 0644 ${handoff}/targets/v$version.pub.tmp
            mv ${handoff}/targets/v$version.pub.tmp ${handoff}/targets/v$version.pub
          done
      fi

      # Rotate the AD bind account once so the bootstrap password stops working.
      if vault secrets list -format=json | jq -e '."ldap/"' >/dev/null && [ ! -e $B/.ldap-root-rotated ]; then
        vault write -f ldap/rotate-root && touch $B/.ldap-root-rotated
      fi
    '';
  };

  # Keep the targets' copy of the agent-approval public keys current: the key
  # auto-rotates, and approvals signed with a new version must still verify.
  systemd.services.agent-approval-keys = {
    description = "Export agent-approval public keys for the targets";
    after = [ "vault-bootstrap.service" ];
    path = [ hc.vault pkgs.jq pkgs.coreutils ];
    serviceConfig = { Type = "oneshot"; UMask = "0022"; };
    script = common + ''
      export VAULT_TOKEN=$(jq -r .root_token $B/init.json)
      vault read -format=json transit/keys/agent-approvals 2>/dev/null |
        jq -r '.data.keys | to_entries[] | "\(.key) \(.value.public_key)"' |
        while read -r version key; do
          printf '%s' "$key" > ${handoff}/targets/v$version.pub.tmp
          mv ${handoff}/targets/v$version.pub.tmp ${handoff}/targets/v$version.pub
        done
    '';
  };
  systemd.timers.agent-approval-keys = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "10min"; OnUnitActiveSec = "1h"; };
  };

  # Re-run the bootstrap while OIDC login is still waiting on Keycloak.
  systemd.services.vault-oidc-retry = {
    description = "Retry Vault OIDC setup";
    unitConfig.ConditionPathExists = "${bootstrapDir}/.oidc-pending";
    serviceConfig.Type = "oneshot";
    script = "${pkgs.systemd}/bin/systemctl restart vault-bootstrap.service";
  };
  systemd.timers.vault-oidc-retry = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "15min"; OnUnitActiveSec = "15min"; };
  };

  # Re-unseal if Vault restarts on its own (it comes back sealed).
  systemd.services.vault-unseal = {
    description = "Unseal Vault if sealed";
    after = [ "vault-bootstrap.service" ];
    path = [ hc.vault pkgs.jq pkgs.coreutils ];
    serviceConfig.Type = "oneshot";
    script = common + ''
      [ -s $B/init.json ] || exit 0
      unseal
    '';
  };
  systemd.timers.vault-unseal = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "5min"; OnUnitActiveSec = "1min"; };
  };

  # Vault's own AD bind password, rotated weekly. (Built-in automated root
  # rotation is Enterprise-only, so a timer calls rotate-root instead.)
  systemd.services.vault-ldap-rotate-root = {
    description = "Rotate Vault's AD bind password";
    path = [ hc.vault pkgs.jq pkgs.coreutils ];
    serviceConfig.Type = "oneshot";
    script = common + ''
      export VAULT_TOKEN=$(jq -r .root_token $B/init.json)
      vault secrets list -format=json | jq -e '."ldap/"' >/dev/null || exit 0
      vault write -f ldap/rotate-root
    '';
  };
  systemd.timers.vault-ldap-rotate-root = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnCalendar = "weekly"; Persistent = true; };
  };
}
