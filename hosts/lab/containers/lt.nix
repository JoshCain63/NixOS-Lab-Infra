# lt01–lt05 — Linux targets reached through Boundary.
#
# Login is a single-use password from Vault's SSH OTP engine, brokered to the
# user by Boundary. sshd hands the password to vault-ssh-helper (via PAM),
# which checks it against Vault's unauthenticated ssh-otp/verify endpoint.
# The target holds no secrets at all; each password works exactly once.
#
# SSH is reachable only from Boundary's worker (hb01): the firewall accepts
# tcp/22 from that address alone, and sshd only lets `ops` in from it. So
# every session goes through Boundary, and therefore through pam-review.
#
# The ops agent (ag01) logs in as `agent`, also only via Boundary with an OTP,
# and sshd forces every agent login into agent-gate (scripts/agent_gate.py):
# named tools only, no shell; Tier 1 actions need a human approval signed
# with Vault transit and verified here. Gate decisions go to Wazuh.
{ name, target }:
{ config, pkgs, lib, ... }:

let
  hc = import ../../../pkgs/hashicorp.nix { inherit pkgs; };
  worker = (import ../network.nix).boundaryWorker;
  pam = "${pkgs.linux-pam}/lib/security";

  # --- agent gate ---------------------------------------------------------
  gateSrc = ../../../scripts/agent_gate.py;
  gatePath = "/run/wrappers/bin:" + lib.makeBinPath [
    pkgs.systemd pkgs.coreutils pkgs.iproute2 pkgs.openssl
  ] + ":/run/current-system/sw/bin";
  # Root helper for Tier 1 (the only sudo rule). Re-validates the request and
  # the approval signature itself; reads the request on stdin, no arguments.
  gateRoot = pkgs.writeShellScript "agent-gate-root" ''
    export PATH=${gatePath}
    exec ${pkgs.python3}/bin/python3 ${gateSrc} --root
  '';
  gate = pkgs.writeShellScript "agent-gate" ''
    export PATH=${gatePath}
    export AGENT_GATE_ROOT=${gateRoot}
    exec ${pkgs.python3}/bin/python3 ${gateSrc}
  '';

  helperConfig = pkgs.writeText "vault-ssh-helper.hcl" ''
    vault_addr        = "https://hv01.lab.internal"
    ca_cert           = "/var/lib/step-ca/root_ca.crt"
    tls_skip_verify   = false
    ssh_mount_point   = "ssh-otp"
    allowed_roles     = "*"
    allowed_cidr_list = "${target.ip}/32"
  '';
in
{
  networking.hostName = name;
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];
  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  system.stateVersion = "26.05";

  environment.systemPackages = [ hc.vault-ssh-helper ];

  # Login banner showing what this host holds.
  environment.etc."motd".text = ''
    ${name} - ${target.role}
    Data: ${target.data}
    Risk: ${toString target.risk}/5 (${target.tier})
  '';

  # The account Boundary sessions log in as. No password: only OTPs work.
  users.users.ops = {
    isNormalUser = true;
    hashedPassword = "!";
  };

  # The ops agent's account: OTP only, and every login is forced into the gate.
  # systemd-journal lets the read-only tools see unit logs.
  users.users.agent = {
    isNormalUser = true;
    hashedPassword = "!";
    extraGroups = [ "systemd-journal" ];
  };

  environment.etc."agent-gate.json".text = builtins.toJSON {
    host = name;
    restartable = [ "demo-app.service" ];
    port_baseline = [ 22 ];
    cert_paths = [ "/var/lib/step-ca/root_ca.crt" ];
    approval_keys_dir = "/var/lib/agent-approvals"; # public keys from hv01 (read-only mount)
    used_ids_path = "/var/lib/agent-gate/used-approvals"; # root-only: replay protection
  };
  systemd.tmpfiles.rules = [ "d /var/lib/agent-gate 0700 root root -" ];

  # Exactly one sudo rule: the root helper, no arguments.
  security.sudo.extraRules = [{
    users = [ "agent" ];
    commands = [{ command = "${gateRoot}"; options = [ "NOPASSWD" ]; }];
  }];

  # Gate decisions -> Wazuh, read straight from the journal.
  imports = [ (import ./wazuh-forward.nix { program = "agent-gate"; tag = "agent-gate"; }) ];

  # Demo service for the "failed service" scenario. `lab-demo break-service`
  # drops /run/demo-app/crash-once; the next start fails with a clear error
  # and consumes the flag, so an approved restart brings it back.
  systemd.services.demo-app = {
    description = "Demo application (agent scenarios)";
    wantedBy = [ "multi-user.target" ];
    serviceConfig.RuntimeDirectory = "demo-app";
    serviceConfig.RuntimeDirectoryPreserve = true;
    script = ''
      if [ -e /run/demo-app/crash-once ]; then
        rm -f /run/demo-app/crash-once
        echo "demo-app: fatal: cannot connect to database (connection refused, 192.168.100.250:5432)" >&2
        exit 1
      fi
      echo "demo-app: started"
      exec sleep infinity
    '';
  };

  # Only Boundary's worker may reach sshd. Anything else (the host, other
  # containers) is dropped and logged as a refused connection. NixOS runs
  # extraCommands just before its final drop rule.
  networking.firewall = {
    logRefusedConnections = true;
    extraCommands = ''
      iptables -A nixos-fw -p tcp --dport 22 -s ${worker} -j nixos-fw-accept
    '';
  };

  services.openssh = {
    enable = true;
    openFirewall = false;
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = true;
      AuthenticationMethods = "keyboard-interactive";
      UsePAM = true;
      PermitRootLogin = "no";
      # Second layer: even if the firewall were open, only from the worker.
      # The agent only on in-scope hosts (not lt05): a second layer behind
      # Boundary, which already refuses it there.
      AllowUsers = [ "ops@${worker}" ] ++ lib.optional target.agent_scope "agent@${worker}";
    };
    # The agent never gets a shell: every login runs the gate, nothing else.
    extraConfig = ''
      Match User agent
        ForceCommand ${gate}
        PermitTTY no
        AllowTcpForwarding no
        AllowAgentForwarding no
        X11Forwarding no
        PermitTunnel no
    '';
  };

  # Replace sshd's PAM stack: auth succeeds only if Vault accepts the OTP.
  security.pam.services.sshd.text = lib.mkForce ''
    account  required  ${pam}/pam_unix.so
    auth     requisite ${pam}/pam_exec.so quiet expose_authtok log=/var/log/vault-ssh.log ${hc.vault-ssh-helper}/bin/vault-ssh-helper -config=${helperConfig}
    auth     optional  ${pam}/pam_unix.so not_set_pass use_first_pass nodelay
    password required  ${pam}/pam_deny.so
    session  required  ${pam}/pam_env.so conffile=/etc/pam/environment readenv=0
    session  required  ${pam}/pam_unix.so
    session  optional  ${pam}/pam_motd.so motd=/etc/motd
  '';
}
