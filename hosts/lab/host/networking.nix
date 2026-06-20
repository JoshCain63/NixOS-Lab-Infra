{ config, pkgs, ... }:

{
  networking.bridges.br-lab.interfaces = [];

  networking.interfaces.br-lab.ipv4.addresses = [{
    address = "192.168.100.1";
    prefixLength = 24;
  }];

  networking.nameservers = [ "127.0.0.1" ];
  networking.search = [ "lab.internal" ];

  networking.networkmanager.dns = "none";

  services.unbound = {
    enable = true;

    enableRootTrustAnchor = false;

    settings = {
      server = {
        interface = [ "127.0.0.1" "192.168.100.1" ];
        access-control = [
          "127.0.0.0/8 allow"
          "192.168.100.0/24 allow"
        ];
        do-ip4 = true;
        do-udp = true;
        do-tcp = true;
      };

      # stub-zone — treat dc01 as the authoritative NS for lab.internal.
      stub-zone = [
        {
          name = "lab.internal.";
          stub-addr = "192.168.100.10";
        }
        {
          name = "ad.lab.internal.";
          stub-addr = "192.168.100.10";
        }
      ];

      # Public internet DNS — always reachable, independent of dc01.
      forward-zone = [
        {
          name = ".";
          forward-addr = [ "1.1.1.1" "8.8.8.8" ];
        }
      ];
    };
  };

  # Trust br-lab entirely — containers need to reach host services freely
  # (step-ca :9000, chrony :123, the unbound above on :53, etc.).
  networking.firewall.trustedInterfaces = [ "br-lab" ];

  # Custom nftables for FORWARD and NAT — the NixOS firewall handles INPUT.
  networking.nftables.enable = true;
  networking.nftables.ruleset = ''
    table inet filter {
      chain forward {
        type filter hook forward priority 0;

        # allow return traffic for established connections
        ct state { established, related } accept

        # allow internal lab traffic
        ip saddr 192.168.100.0/24 ip daddr 192.168.100.0/24 accept

        # allow Entra sync box outbound (win-srv01)
        ip saddr 192.168.100.22 tcp dport { 80, 443 } accept

        # allow mp01 (MidPoint) to reach win-srv01 AD on LDAP
        ip saddr 192.168.100.13 ip daddr 192.168.100.22 tcp dport 389 accept

        # allow dc01 DNS forwarding outbound
        ip saddr 192.168.100.10 udp dport 53 accept
        ip saddr 192.168.100.10 tcp dport 53 accept

        # drop everything else from lab
        ip saddr 192.168.100.0/24 drop
      }
    }

    table ip nat {
      chain postrouting {
        type nat hook postrouting priority 100;

        # masquerade outbound internet traffic for containers with external access
        ip saddr { 192.168.100.10, 192.168.100.22 } oifname != "br-lab" masquerade;
      }
    }
  '';

  # Serve NTP to the lab — containers can't adjust their own clocks
  services.chrony = {
    enable = true;
    extraConfig = ''
      local stratum 3
      allow 192.168.100.0/24
    '';
  };
}
