{ config, pkgs, ... }:

{
  # Trust the entra bridge so the host can reach VMs freely
  # (SPICE console on autoport, virt-viewer, guest-agent socket).
  # The FORWARD chain below is what actually constrains VM traffic.
  networking.firewall.trustedInterfaces = [ "virbr-entra" ];

  # NixOS nftables replaces iptables system-wide.  libvirt uses the
  # iptables-nft shim and coexists fine; its dnsmasq instance on
  # virbr-entra still handles DHCP + DNS for the guests without
  # needing any extra rules here.
  networking.nftables.enable = true;
  networking.nftables.ruleset = ''
    table inet filter {
      chain forward {
        type filter hook forward priority 0;

        # allow return traffic for established connections
        ct state { established, related } accept

        # allow intra-entra traffic (AD/Kerberos/LDAP between DC and Win11)
        ip saddr 192.168.200.0/24 ip daddr 192.168.200.0/24 accept

        # allow DC outbound (Entra Connect / Cloud Sync needs 80 + 443)
        ip saddr 192.168.200.10 tcp dport { 80, 443 } accept

        # allow Win11 outbound (Windows Update, Entra registration, domain join)
        ip saddr 192.168.200.20 tcp dport { 80, 443 } accept

        # drop everything else originating from the entra subnet —
        # VMs cannot reach the host's lab bridge, other subnets, or
        # any port beyond 80/443 on the internet
        ip saddr 192.168.200.0/24 drop
      }
    }

    table ip nat {
      chain postrouting {
        type nat hook postrouting priority 100;

        # masquerade outbound internet traffic for the two entra VMs
        ip saddr 192.168.200.0/24 oifname != "virbr-entra" masquerade;
      }
    }
  '';
}
