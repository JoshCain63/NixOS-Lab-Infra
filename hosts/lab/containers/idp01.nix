{ config, pkgs, lib, ... }:

{
  networking.hostName = "idp01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.10" ];

  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.10
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 80 ];
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
    KC_BOOTSTRAP_ADMIN_PASSWORD = "password123";
  };

  services.chrony.servers = [ "192.168.100.1" ];
}
