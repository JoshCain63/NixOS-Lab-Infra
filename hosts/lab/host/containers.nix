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
      "/var/lib/handoff" = {
        hostPath   = "/mnt/wd_blue/containers/handoff/idp01";
        isReadOnly = true;
      };
      "/etc/lab/terraform" = {
        hostPath   = "/mnt/wd_blue/containers/idp01/terraform";
        isReadOnly = true;
      };
      "/var/lib/keycloak-terraform" = {
        hostPath   = "/mnt/wd_blue/containers/idp01/terraform-state";
        isReadOnly = false;
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
      "/var/lib/handoff" = {
        hostPath   = "/mnt/wd_blue/containers/handoff/mp01";
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

  # hv01 — HashiCorp Vault
  containers.hv01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.17/24";

    bindMounts = {
      "/var/lib/vault" = {
        hostPath = "/mnt/wd_blue/containers/hv01/data";
        isReadOnly = false;
      };
      "/var/lib/vault-bootstrap" = {
        hostPath = "/mnt/wd_blue/containers/hv01/bootstrap";
        isReadOnly = false;
      };
      "/etc/lab/terraform" = {
        hostPath = "/mnt/wd_blue/containers/hv01/terraform";
        isReadOnly = true;
      };
      "/var/lib/handoff" = {
        hostPath = "/mnt/wd_blue/containers/handoff";
        isReadOnly = false;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/hv01.nix;
  };

  # hb01 — HashiCorp Boundary
  containers.hb01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.18/24";

    bindMounts = {
      "/var/lib/boundary" = {
        hostPath = "/mnt/wd_blue/containers/hb01/boundary";
        isReadOnly = false;
      };
      "/var/lib/postgresql" = {
        hostPath = "/mnt/wd_blue/containers/hb01/postgresql";
        isReadOnly = false;
      };
      "/etc/lab/terraform" = {
        hostPath = "/mnt/wd_blue/containers/hb01/terraform";
        isReadOnly = true;
      };
      "/var/lib/handoff" = {
        hostPath = "/mnt/wd_blue/containers/handoff/hb01";
        isReadOnly = true;
      };
      "/var/lib/boundary-export" = {
        hostPath = "/mnt/wd_blue/containers/hb01/export";
        isReadOnly = false;
      };
      "/var/lib/boundary-events" = {
        hostPath = "/mnt/wd_blue/containers/hb01/events";
        isReadOnly = false;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/hb01.nix;
  };

  # ai01 — local LLM (Ollama) and the pam-review session reviewer
  containers.ai01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.19/24";

    bindMounts = {
      "/var/lib/ollama" = {
        hostPath = "/mnt/wd_blue/containers/ai01/ollama";
        isReadOnly = false;
      };
      "/var/lib/pam-review" = {
        hostPath = "/mnt/wd_blue/containers/ai01/pam-review";
        isReadOnly = false;
      };
      "/var/lib/handoff" = {
        hostPath = "/mnt/wd_blue/containers/handoff/ai01";
        isReadOnly = true;
      };
      # The ops agent's task ledger (ag01), for scoring its tasks.
      "/var/lib/ops-agent-ledger" = {
        hostPath = "/mnt/wd_blue/containers/ag01/state";
        isReadOnly = true;
      };
      # Target risk export from hb01 (used by `pam-review eval`).
      "/var/lib/boundary-export" = {
        hostPath = "/mnt/wd_blue/containers/hb01/export";
        isReadOnly = true;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/ai01.nix;
  };

  # wz01 — Wazuh (SOC view of pam-review findings and Boundary's event trail)
  containers.wz01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.20/24";

    # The Wazuh post-start units (wazuh-api-rbac, wazuh-saved-objects) block
    # this container's multi-user.target while they poll for the indexer, the
    # manager API and the dashboard - wazuh-saved-objects alone retries for up
    # to 40 minutes. With the default 1-minute timeoutStartSec systemd decided
    # the container had failed to start and killed it, every minute, forever
    # (NRestarts reached 35), which restarted all three Wazuh containers under
    # it. That stayed invisible while Wazuh was broken, because the units
    # failed immediately instead of waiting.
    timeoutStartSec = "20min";
    extraFlags = [ "--capability=CAP_SYS_ADMIN" "--capability=CAP_BPF" "--capability=CAP_NET_ADMIN" ];

    # The Wazuh images carry /dev/console as a char device (5:1) inside their
    # layers, and podman has to recreate it with mknod while unpacking them.
    # Every systemd unit inside this container inherits a device filter that
    # refuses that, so image load failed with
    #   unpacking failed (error: exit status 1; output: operation not permitted)
    # and container creation failed with
    #   creating read-write layer with ID "<id>": operation not permitted
    # It had to be allowed HERE rather than on the inner units: nspawn replaces
    # /dev/console inside the container with a symlink, so an inner
    # DeviceAllow=/dev/console resolves to 0:0 and matches nothing. On the host
    # /dev/console really is 5:1, so the rule resolves correctly.
    # (Confusingly, running podman by hand always worked, because
    # `nixos-container run` nsenters from the host and so never enters the
    # container's cgroup or its device filter.)
    allowedDevices = [
      { node = "/dev/console"; modifier = "rwm"; }
    ];

    bindMounts = {
      "/var/lib/wazuh" = {
        hostPath = "/mnt/wd_blue/containers/wz01/wazuh";
        isReadOnly = false;
      };
      # podman's image store (vfs): several GB, so on the drive.
      "/var/lib/containers" = {
        hostPath = "/mnt/wd_blue/containers/wz01/containers";
        isReadOnly = false;
      };
      "/var/lib/handoff" = {
        hostPath = "/mnt/wd_blue/containers/handoff/wz01";
        isReadOnly = true;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/wz01.nix;
  };

  # ag01 — ops agent (AI non-human identity running named tools)
  containers.ag01 = {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "192.168.100.21/24";

    bindMounts = {
      "/var/lib/ops-agent" = {
        hostPath = "/mnt/wd_blue/containers/ag01";
        isReadOnly = false;
      };
      "/var/lib/handoff" = {
        hostPath = "/mnt/wd_blue/containers/handoff/ag01";
        isReadOnly = true;
      };
      # hb01 publishes the agent LDAP auth method id here. Boundary does not
      # return LDAP auth methods in the anonymous auth-method list, so the
      # agent cannot discover it and login fails at boundary_login with
      # "no ldap auth method in scope global".
      "/var/lib/boundary-export" = {
        hostPath   = "/mnt/wd_blue/containers/hb01/export";
        isReadOnly = true;
      };
      "/var/lib/step-ca/root_ca.crt" = {
        hostPath   = "/var/lib/step-ca/certs/root_ca.crt";
        isReadOnly = true;
      };
    };

    config = import ../containers/ag01.nix;
  };
}
