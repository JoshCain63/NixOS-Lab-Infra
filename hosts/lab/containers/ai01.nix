# ai01 — local LLM for AI-assisted PAM review.
#
# - Ollama serving Qwen2.5-3B-Instruct, built offline from a pinned GGUF. On
#   the GTX 980 via Vulkan when features.gpu is on (host side: host/gpu.nix),
#   otherwise on the CPU.
# - pam-review (scripts/pam_review) every 2 minutes: reads Boundary sessions
#   as the read-only pam-reviewer account, scores them deterministically, and
#   asks the model to triage the ones at or above the threshold.
# - The report at https://ai01.lab.internal is behind Keycloak (oauth2-proxy,
#   IT department only). Findings also go to Wazuh on wz01 for the SOC.
# - pam-review is itself an AI agent, so it is governed like the ops agent:
#   with features.pamReviewNhi it logs in as svc-pam-review (midPoint sponsor
#   + expiry -> AD -> Keycloak client credentials -> Vault JWT -> Boundary
#   LDAP), fresh each run. Before that (legacy): the local pam-reviewer
#   password from Vault KV (5-minute IP-bound AppRole token). Either way the
#   password is never stored on this container's disk.
#
# Report only: nothing here can block or cancel a session.
{ config, pkgs, lib, ... }:

let
  models = import ../../../pkgs/models.nix { inherit pkgs; };
  features = import ../features.nix;
  gpu = features.gpu;
  nhi = features.pamReviewNhi;
  net = import ../network.nix;
  model = models.qwen25-3b-instruct;
  scripts = ../../../scripts;
  rootCa = "/var/lib/step-ca/root_ca.crt";

  modelfile = pkgs.writeText "Modelfile" ''
    FROM ${model.gguf}
    PARAMETER temperature 0
    PARAMETER num_ctx 4096
  '';

  reviewEnv = {
    PYTHONPATH = "${scripts}";
    PYTHONDONTWRITEBYTECODE = "1";
    # Pin the tz database the scorer uses for business hours.
    PYTHONTZPATH = "${pkgs.tzdata}/share/zoneinfo";
    BOUNDARY_ADDR = "https://hb01.lab.internal";
    BOUNDARY_CACERT = rootCa;
    OLLAMA_URL = "http://127.0.0.1:11434";
    PAM_REVIEW_MODEL = model.name;
    # The ops agent's task ledger (ag01, read-only mount) and its account.
    PAM_REVIEW_AGENT_LEDGER = "/var/lib/ops-agent-ledger/ledger.ndjson";
    PAM_REVIEW_AGENT_ACCOUNTS = "svc-agent-ops";
  } // (if nhi then {
    # Governed identity: Keycloak -> Vault JWT -> Boundary LDAP (svc-pam-review).
    PAM_REVIEW_IDENTITY = "/etc/pam-review-identity.json";
  } else {
    # Legacy: pam-reviewer's password from Vault KV via AppRole.
    VAULT_ADDR = "https://hv01.lab.internal";
    VAULT_CACERT = rootCa;
  });

  # `pam-review eval` / `pam-review report` for manual runs inside ai01.
  pamReviewCli = pkgs.writeShellScriptBin "pam-review" ''
    ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "export ${k}=${lib.escapeShellArg v}") reviewEnv)}
    exec ${pkgs.python3}/bin/python3 -m pam_review "$@"
  '';
in
{
  # Findings -> Wazuh (wz01). Levels there come from the rule score only.
  imports = [
    (import ./wazuh-forward.nix { file = "/var/lib/pam-review/reports/findings.ndjson"; tag = "pam-review"; })
  ];

  networking.hostName = "ai01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];
  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 80 443 ];
  # Ollama is shared with the ops agent: reachable from ag01 only.
  networking.firewall.extraCommands = ''
    iptables -A nixos-fw -p tcp --dport 11434 -s ${net.ag01} -j nixos-fw-accept
  '';
  system.stateVersion = "26.05";

  environment.systemPackages = [ pamReviewCli ];

  # pam-review's governed identity (non-secret part; the Keycloak client
  # secret is a systemd credential). Same chain as the ops agent on ag01.
  environment.etc."pam-review-identity.json" = lib.mkIf nhi {
    text = builtins.toJSON {
      keycloak_token_url = "https://idp01.lab.internal/realms/lab/protocol/openid-connect/token";
      client_id = "pam-review";
      vault_addr = "https://hv01.lab.internal";
      vault_jwt_path = "jwt-keycloak";
      vault_role = "pam-review";
      account = "svc-pam-review";
      boundary_addr = "https://hb01.lab.internal";
      # Boundary hides LDAP auth methods from the anonymous auth-method list,
      # so the id can't be discovered; hb01 publishes it here from its
      # Terraform output.
      auth_method_id_file = "/var/lib/boundary-export/agent-auth-method-id";
      ca_file = rootCa;
    };
  };

  # --- Ollama ---------------------------------------------------------------
  # Static user so the model store can live on the bind-mounted drive.
  services.ollama = {
    enable = true;
    package = if gpu then pkgs.ollama-vulkan else pkgs.ollama;
    user = "ollama";
    group = "ollama";
    home = "/var/lib/ollama";
    # On the bridge for the ops agent (ag01); the firewall admits only ag01.
    host = "0.0.0.0";
    environmentVariables = {
      # Unload the model soon after the last review. The model only loads for
      # risky sessions, so this frees memory (VRAM or RAM) almost immediately.
      OLLAMA_KEEP_ALIVE = if gpu then "5m" else "1m";
      # Bounded consumption: one request at a time, one model, short queue.
      OLLAMA_NUM_PARALLEL = "1";
      OLLAMA_MAX_LOADED_MODELS = "1";
      OLLAMA_MAX_QUEUE = "16";
      # Don't keep interactive prompt history on disk.
      OLLAMA_NOHISTORY = "1";
    };
  };
  systemd.services.ollama.serviceConfig = {
    MemoryMax = "6G";
    TasksMax = 256;
    # nixpkgs 26.05 turned DynamicUser on in the ollama module. With it on,
    # systemd insists the state directory lives at /var/lib/private/ollama and
    # tries to migrate the existing /var/lib/ollama into it - which fails with
    # EBUSY, because /var/lib/ollama is the bind mount of the model store on
    # /mnt/wd_blue. Keep the static ollama user this container was built around.
    DynamicUser = lib.mkForce false;
  };

  # NVIDIA's userspace driver compiles GPU code at runtime and needs memory
  # that is both writable and executable, which the module's hardening forbids.
  systemd.services.ollama.serviceConfig.MemoryDenyWriteExecute = lib.mkIf gpu (lib.mkForce false);

  # Model integrity (OWASP LLM: supply chain, data and model poisoning).
  # The GGUF in the Nix store is fixed by its hash, but Ollama's own copy
  # (manifest + content-addressed blobs) lives on the writable drive. So:
  # - the model is registered once from the pinned Modelfile, and the
  #   manifest's fingerprint is recorded in a root-owned file Ollama can't write;
  # - on every boot and daily it's verified: manifest unchanged, every blob it
  #   lists matches its digest, and the weights match the pinned sha256;
  # - only on a mismatch (or a new Modelfile) is it rebuilt.
  # pam-review won't run unless this passed.
  systemd.services.ollama-model = {
    description = "Verify (or register) the ${model.name} model in Ollama";
    after = [ "ollama.service" ];
    requires = [ "ollama.service" ];
    wantedBy = [ "multi-user.target" ];
    environment = {
      OLLAMA_HOST = "127.0.0.1:11434";
      # systemd gives a service no HOME, and ollama 0.40's CLI evaluates
      # envconfig.AsMap() while building its command set, which panics with
      # "$HOME is not defined" before it does anything useful.
      HOME = "/var/lib/ollama";
    };
    path = [ config.services.ollama.package pkgs.curl pkgs.coreutils pkgs.jq ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      StateDirectory = "ollama-integrity"; # /var/lib/ollama-integrity, root-owned
    };
    script = ''
      set -euo pipefail
      for _ in $(seq 1 60); do curl -sf http://127.0.0.1:11434/api/version >/dev/null && break; sleep 2; done

      models=/var/lib/ollama/models
      record=/var/lib/ollama-integrity/${model.name}
      expected="${modelfile}"

      # Ollama 0.40 renamed the manifest tree: manifests/registry.ollama.ai/...
      # became manifests-v2/ollama.com/... . Accept either layout, newest
      # first, so the check keeps working across an Ollama upgrade instead of
      # silently always failing and re-registering.
      manifest_path() {
        local p
        for p in "$models/manifests-v2/ollama.com/library/${model.name}/latest" \
                 "$models/manifests/registry.ollama.ai/library/${model.name}/latest"; do
          if [ -s "$p" ]; then printf '%s\n' "$p"; return 0; fi
        done
        return 1
      }

      verify() {
        local manifest
        manifest=$(manifest_path) || return 1
        [ -s "$record" ] || return 1
        # Recorded for this exact Modelfile, and the manifest is unchanged.
        [ "$(sed -n 1p "$record")" = "$expected" ] || return 1
        [ "$(sha256sum "$manifest" | cut -d' ' -f1)" = "$(sed -n 2p "$record")" ] || return 1
        # The weights layer is the pinned GGUF.
        jq -e --arg d "sha256:${model.sha256}" '[.layers[].digest] | index($d) != null' "$manifest" >/dev/null || return 1
        # Every blob (weights, template, params, config) matches its digest.
        for d in $(jq -r '.config.digest, .layers[].digest' "$manifest"); do
          [ "$(sha256sum "$models/blobs/''${d/:/-}" | cut -d' ' -f1)" = "''${d#sha256:}" ] || return 1
        done
      }

      if verify; then
        echo "${model.name}: verified (manifest, template, parameters, weights)"
        exit 0
      fi

      echo "${model.name}: missing, changed or unverified; registering from the pinned Modelfile"
      ollama rm ${model.name} >/dev/null 2>&1 || true
      rm -f "$models/blobs/sha256-${model.sha256}"   # never reuse an unverified weights blob
      # Ollama 0.40 keeps a per-digest GGUF metadata cache. If it survives the
      # blob deletion above, `ollama create` reports "using existing layer" and
      # does NOT re-copy the weights, leaving a manifest that points at a file
      # we just removed - the model then 404s on every load.
      rm -f "$models/metadata/sha256-${model.sha256}.json"
      ollama create ${model.name} -f "$expected"
      fresh=$(manifest_path) || { echo "Refusing to serve: no manifest after create" >&2; exit 1; }
      printf '%s\n%s\n' "$expected" "$(sha256sum "$fresh" | cut -d' ' -f1)" > "$record"
      verify || { echo "Refusing to serve: fresh model failed verification" >&2; exit 1; }
      echo "${model.name}: registered and verified"
    '';
  };
  systemd.timers.ollama-model = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnCalendar = "daily"; Persistent = true; };
  };

  # --- pam-review ------------------------------------------------------------
  users.users.pam-review = {
    isSystemUser = true;
    group = "pam-review";
    home = "/var/lib/pam-review";
  };
  users.groups.pam-review = {};

  systemd.tmpfiles.rules = [
    "d /var/lib/pam-review 0755 pam-review pam-review -"
    "d /var/lib/pam-review/reports 0755 pam-review pam-review -"
    # The model store is a bind mount of /mnt/wd_blue/containers/ai01/ollama,
    # so on a fresh drive models/ does not exist and ollama's own mount
    # namespacing fails with 226/NAMESPACE before the service ever runs.
    "d /var/lib/ollama 0755 ollama ollama -"
    "d /var/lib/ollama/models 0755 ollama ollama -"
  ];

  systemd.services.pam-review = {
    description = "AI-assisted review of Boundary sessions";
    after = [ "ollama-model.service" "network-online.target" ];
    wants = [ "network-online.target" ];
    requires = [ "ollama-model.service" ]; # only with verified weights
    environment = reviewEnv;
    unitConfig.ConditionPathExists =
      if nhi then "/var/lib/handoff/pam-review-oidc-secret" else "/var/lib/handoff/role_id";
    serviceConfig = {
      Type = "oneshot";
      User = "pam-review";
      Group = "pam-review";
      LoadCredential =
        if nhi
        # Its Keycloak client secret; everything else is fetched per run.
        then [ "client_secret:/var/lib/handoff/pam-review-oidc-secret" ]
        # Legacy AppRole for reading secret/boundary/pam-reviewer (ai01's IP only).
        else [ "role_id:/var/lib/handoff/role_id" "secret_id:/var/lib/handoff/secret_id" ];
      ExecStart = "${pkgs.python3}/bin/python3 -m pam_review run";
      TimeoutStartSec = "30min"; # CPU inference on a backlog can be slow
      UMask = "0022";

      # Least privilege for the process that handles model output and
      # attacker-influenced data (OWASP LLM: excessive agency). It can read
      # Boundary/Vault over the network and write only its own state.
      NoNewPrivileges = true;
      CapabilityBoundingSet = "";
      ProtectSystem = "strict";
      ReadWritePaths = [ "/var/lib/pam-review" ];
      ProtectHome = true;
      PrivateTmp = true;
      PrivateDevices = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectClock = true;
      ProtectHostname = true;
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      MemoryMax = "512M";
    };
  };
  systemd.timers.pam-review = {
    wantedBy = [ "timers.target" ];
    timerConfig = { OnBootSec = "5min"; OnUnitInactiveSec = "2min"; };
  };

  # --- Report: Keycloak login, IT only ---------------------------------------
  # Caddy (TLS) -> oauth2-proxy (OIDC, allowed group IT) -> the report files.
  services.oauth2-proxy = {
    enable = true;
    provider = "keycloak-oidc";
    clientID = "pam-report";
    clientSecretFile = "/var/lib/handoff/pam-report-oidc-secret";
    cookie.secretFile = "/var/lib/handoff/pam-report-cookie-secret";
    cookie.secure = true;
    email.domains = [ "*" ];
    httpAddress = "127.0.0.1:4180";
    upstream = [ "file:///var/lib/pam-review/reports/#/" ];
    reverseProxy = true;
    # Only Caddy (same container) may set X-Forwarded-* headers.
    trustedProxyIP = [ "127.0.0.1" ];
    extraConfig = {
      oidc-issuer-url = "https://idp01.lab.internal/realms/lab";
      provider-ca-file = rootCa;
      redirect-url = "https://ai01.lab.internal/oauth2/callback";
      oidc-email-claim = "preferred_username";
      allowed-group = "IT";
      skip-provider-button = true;
    };
  };
  systemd.services.oauth2-proxy = {
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Restart = lib.mkForce "always";
      RestartSec = "10s";
      # The report files are world-readable; the proxy needs to see them.
      ReadOnlyPaths = [ "/var/lib/pam-review/reports" ];
    };
  };

  services.caddy = {
    enable = true;
    virtualHosts."ai01.lab.internal".extraConfig = ''
      tls {
        ca https://pki.lab.internal:9000/acme/acme/directory
        ca_root ${rootCa}
      }
      reverse_proxy 127.0.0.1:4180
    '';
  };
  systemd.services.caddy.serviceConfig = {
    ReadOnlyPaths = [ "/var/lib/step-ca" ];
    ProtectSystem = "false";
  };
}
