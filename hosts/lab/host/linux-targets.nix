# Defines one container per entry in ../targets.nix (lt01–lt05).
{ lib, ... }:

{
  containers = lib.mapAttrs (name: target: {
    autoStart = true;
    privateNetwork = true;
    hostBridge = "br-lab";
    localAddress = "${target.ip}/24";

    bindMounts."/var/lib/step-ca/root_ca.crt" = {
      hostPath = "/var/lib/step-ca/certs/root_ca.crt";
      isReadOnly = true;
    };
    # Public keys for verifying agent approvals (exported by hv01; not secret).
    bindMounts."/var/lib/agent-approvals" = {
      hostPath = "/mnt/wd_blue/containers/handoff/targets";
      isReadOnly = true;
    };

    config = import ../containers/lt.nix { inherit name target; };
  }) (import ../targets.nix);
}
