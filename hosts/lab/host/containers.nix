{ config, pkgs, ... }:

{
  containers.dc01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.10/24";
    config = import ../containers/dc01.nix;
  };

  containers.idp01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.11/24";
    extraFlags = [ "--capability=CAP_SYS_ADMIN" "--capability=CAP_BPF" "--capability=CAP_NET_ADMIN" ];

    bindMounts = {
      "/var/lib/keycloak-db-password" = {
        hostPath = "/var/lib/keycloak-db-password";
        isReadOnly = true;
      };
      "/var/lib/container-images" = {
        hostPath = "/nix/store";
        isReadOnly = true;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/idp01.nix;
  };

  containers.svc01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.12/24";

    bindMounts = {
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/svc01.nix;
  };

  containers.mp01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.13/24";
    extraFlags = [ "--capability=CAP_SYS_ADMIN" "--capability=CAP_BPF" "--capability=CAP_NET_ADMIN" ];

    bindMounts = {
      "/opt/midpoint/var" = {
        hostPath = "/mnt/wd_blue/containers/mp01/var";
        isReadOnly = false;
      };
      "/var/lib/container-images" = {
        hostPath = "/nix/store";
        isReadOnly = true;
      };
      "/srv/hr" = {
        hostPath = "/mnt/wd_blue/containers/hr01/data";
        isReadOnly = true;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/mp01.nix;
  };

  # hr01 — HR Simulator: simple web UI + CSV file for MidPoint to consume.
  containers.hr01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.16/24";

    bindMounts = {
      "/var/lib/hr" = {
        hostPath = "/mnt/wd_blue/containers/hr01/data";
        isReadOnly = false;
      };
    };

    config = import ../containers/hr01.nix;
  };

  containers.bh01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.14/24";
    extraFlags = [ "--capability=CAP_SYS_ADMIN" "--capability=CAP_BPF" "--capability=CAP_NET_ADMIN" ];

    bindMounts = {
      "/var/lib/bloodhound" = {
        hostPath = "/mnt/wd_blue/containers/bh01/data";
        isReadOnly = false;
      };
      "/var/lib/container-images" = {
        hostPath = "/nix/store";
        isReadOnly = true;
      };
    };

    config = import ../containers/bh01.nix;
  };
}
