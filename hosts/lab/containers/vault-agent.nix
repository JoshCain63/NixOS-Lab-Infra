# Vault Agent that keeps one Vault-rotated AD password rendered to a file.
# Logs in with the AppRole hv01 hands over in /var/lib/handoff; it
# stays inactive until that exists (i.e. until AD rotation is enabled).
{ account, destination }:
{ pkgs, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
in
{
  services.vault-agent.instances.ad = {
    package = hc.vault;
    settings = {
      vault = {
        address = "https://hv01.lab.internal";
        ca_cert = "/var/lib/step-ca/root_ca.crt";
      };
      auto_auth.method = [{
        type = "approle";
        config = {
          role_id_file_path = "/var/lib/handoff/role_id";
          secret_id_file_path = "/var/lib/handoff/secret_id";
          remove_secret_id_file_after_reading = false;
        };
      }];
      template = [{
        inherit destination;
        contents = ''{{ with secret "ldap/static-cred/${account}" }}{{ .Data.password }}{{ end }}'';
        # Readable by the (DynamicUser) service that consumes it.
        perms = "0444";
      }];
    };
  };

  # The directory always exists, so consumers can point at it before rotation is on.
  systemd.tmpfiles.rules = [ "d ${dirOf destination} 0755 root root -" ];

  # Start when the AppRole appears (hv01 may hand it over after we boot).
  systemd.services.vault-agent-ad.unitConfig.ConditionPathExists = "/var/lib/handoff/role_id";
  systemd.paths.vault-agent-ad = {
    wantedBy = [ "multi-user.target" ];
    pathConfig.PathExists = "/var/lib/handoff/role_id";
  };
}
