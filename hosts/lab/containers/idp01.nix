{ config, pkgs, lib, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
  adminPassword = "password123"; # Keycloak bootstrap admin (lab only)
in
{
  # Vault-rotated svc-keycloak password -> Keycloak's file vault. Use it in
  # User Federation > ldap > Bind credential as ${vault.svc-keycloak}.
  imports = [
    (import ./vault-agent.nix {
      account = "svc-keycloak";
      destination = "/run/keycloak-vault/lab_svc-keycloak";
    })
  ];

  networking.hostName = "idp01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.10" ];

  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.10
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 80 443 ];
  system.stateVersion = "25.11";

  services.keycloak = {
    enable = true;
    database.host = "localhost";
    database.passwordFile = "/var/lib/keycloak-db-password";
    settings = {
      hostname = "idp01.lab.internal";
      hostname-strict = false;
      proxy-headers = "xforwarded";
      http-enabled = true;
      http-port    = 80;
      vault        = "file";
      vault-dir    = "/run/keycloak-vault";
    };
  };

  services.postgresql = {
    enable = true;
    ensureDatabases = [ "keycloak" ];
    ensureUsers = [{
      name = "keycloak";
      ensureDBOwnership = true;
    }];
    authentication = lib.mkAfter ''
      host keycloak keycloak 127.0.0.1/32 trust
    '';
  };

  systemd.services.keycloakPostgreSQLInit = lib.mkForce {
    description = "Keycloak PostgreSQL init (nspawn stub)";
    after    = [ "postgresql.service" ];
    requires = [ "postgresql.service" ];
    before   = [ "keycloak.service" ];
    wantedBy = [ "keycloak.service" ];
    serviceConfig = {
      Type            = "oneshot";
      RemainAfterExit = true;
    };
    script = ":";
  };

  systemd.services.keycloak.serviceConfig = {
    LoadCredential = lib.mkForce [];
    Environment = "CREDENTIALS_DIRECTORY=/var/lib";
  };

  systemd.services.keycloak.environment = {
    KC_BOOTSTRAP_ADMIN_USERNAME = "admin";
    KC_BOOTSTRAP_ADMIN_PASSWORD = adminPassword;
  };

  # HTTPS for OIDC clients that require a TLS issuer (Boundary, Vault):
  # https://idp01.lab.internal/realms/lab. Plain http on :80 stays for
  # oauth2-proxy. Keycloak owns :80, so Caddy's HTTP side moves to :8081 and
  # certificates use the TLS-ALPN challenge on :443 instead of HTTP.
  services.caddy = {
    enable = true;
    globalConfig = ''
      http_port 8081
      auto_https disable_redirects
    '';
    virtualHosts."https://idp01.lab.internal".extraConfig = ''
      tls {
        issuer acme {
          dir https://pki.lab.internal:9000/acme/acme/directory
          trusted_roots /var/lib/step-ca/root_ca.crt
          disable_http_challenge
        }
      }
      reverse_proxy 127.0.0.1:80
    '';
  };
  systemd.services.caddy.serviceConfig = {
    ReadOnlyPaths = [ "/var/lib/step-ca" ];
    ProtectSystem = "false";
  };

  # OIDC clients for Boundary and Vault, from terraform/keycloak (synced onto
  # the drive by the host). Waits for the client secrets from hv01.
  systemd.services.keycloak-terraform = {
    description = "Configure Keycloak OIDC clients from Terraform";
    wantedBy = [ "multi-user.target" ];
    after = [ "keycloak.service" ];
    wants = [ "keycloak.service" ];
    path = [ hc.terraform pkgs.curl pkgs.coreutils pkgs.findutils ];
    environment = {
      HOME = "/var/lib/keycloak-terraform";
      CHECKPOINT_DISABLE = "1";
      TF_IN_AUTOMATION = "1";
      TF_VAR_admin_password = adminPassword;
    };
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      UMask = "0077";
      TimeoutStartSec = "30min";
    };
    script = ''
      set -uo pipefail
      until curl -sf http://127.0.0.1/realms/lab/.well-known/openid-configuration >/dev/null; do
        echo "Waiting for Keycloak..."; sleep 10
      done
      for c in boundary vault wazuh pam-report ops-agent pam-review; do
        until [ -s /var/lib/handoff/$c-oidc-secret ]; do
          echo "Waiting for the $c OIDC client secret from hv01..."; sleep 10
        done
      done

      W=/var/lib/keycloak-terraform/work
      mkdir -p $W
      find $W -maxdepth 1 \( -name '*.tf' -o -name '*.tfvars' -o -name '*.tfvars.json' \) -delete
      cp --no-preserve=mode /etc/lab/terraform/* $W/
      terraform -chdir=$W init -input=false -plugin-dir=${hc.terraformPlugins}
      terraform -chdir=$W apply -input=false -auto-approve
    '';
  };

  services.chrony.servers = [ "192.168.100.1" ];
}
