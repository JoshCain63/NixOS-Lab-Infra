{ config, pkgs, lib, ... }:

let
  targets = import ../targets.nix;
in
{
  networking.hostName = "dc01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "127.0.0.1" ];
  system.stateVersion = "25.11";
  networking.firewall.allowedTCPPorts = [ 53 ];
  networking.firewall.allowedUDPPorts = [ 53 ];
  services.unbound = {
    enable = true;
    enableRootTrustAnchor = false;
    settings = {
      server = {
        interface = [ "0.0.0.0" ];
        access-control = [ "192.168.100.0/24 allow" "127.0.0.1/32 allow" ];
        do-ip4 = true;
        do-udp = true;
        do-tcp = true;
        local-zone = [ ''"lab.internal." static'' ''"ad.lab.internal." static'' ];
        local-data = [
          ''"dc01.lab.internal. A 192.168.100.10"''
          ''"idp01.lab.internal. A 192.168.100.11"''
          ''"svc01.lab.internal. A 192.168.100.12"''
          ''"mp01.lab.internal. A 192.168.100.13"''
          ''"bh01.lab.internal. A 192.168.100.14"''
          ''"tp01.lab.internal. A 192.168.100.15"''
          ''"hr01.lab.internal. A 192.168.100.16"''
          ''"hv01.lab.internal. A 192.168.100.17"''
          ''"hb01.lab.internal. A 192.168.100.18"''
          ''"ai01.lab.internal. A 192.168.100.19"''
          ''"wz01.lab.internal. A 192.168.100.20"''
          ''"ag01.lab.internal. A 192.168.100.21"''
          ''"whoami.lab.internal. A 192.168.100.12"''
          ''"pki.lab.internal. A 192.168.100.1"''
          ''"win-srv01.ad.lab.internal. A 192.168.100.22"''
        ] ++ lib.mapAttrsToList (name: t: ''"${name}.lab.internal. A ${t.ip}"'') targets;
      };
      forward-zone = [
        {
          name = ".";
          forward-addr = [ "1.1.1.1" "8.8.8.8" ];
        }
      ];
    };
  };
}
