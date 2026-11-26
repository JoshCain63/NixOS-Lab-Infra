# wz01 — Wazuh SIEM for the SOC (manager, indexer, dashboard).
#
# Receives these streams over TCP syslog (port 514), from nowhere else:
#   - pam-review findings from ai01 (rule levels come from the score only),
#   - Boundary's own event trail from hb01 (independent of ai01),
#   - Vault's audit log from hv01,
#   - the ops agent's ledger (ag01) and agent-gate decisions (targets).
# Rules: hosts/lab/wazuh/lab_rules.xml. Decoders: hosts/lab/wazuh/lab_decoders.xml.
#
# Wazuh isn't in nixpkgs, so the official 4.14.10 images run under podman
# (same pattern as mp01/bh01). Internal TLS uses a Wazuh-only CA made on
# first boot; browsers reach the dashboard through Caddy with a step-ca cert.
# SOC login: Keycloak OIDC, IT department only; local admin is break-glass.
{ config, pkgs, lib, ... }:

let
  net = import ../network.nix;
  wz = ../wazuh;
  version = "4.14.10";
  W = "/var/lib/wazuh";
  certs = "${W}/certs";
  rendered = "${W}/config";
  handoff = "/var/lib/handoff";
  stepRoot = "/var/lib/step-ca/root_ca.crt";

  # Image hashes: from the first build (Nix prints "got: sha256-..."). To
  # upgrade, change the digest, set the hash to lib.fakeHash and rebuild.
  image = name: digest: hash: pkgs.dockerTools.pullImage {
    imageName = "wazuh/${name}";
    imageDigest = digest;
    inherit hash;
    finalImageName = "wazuh/${name}";
    finalImageTag = version;
    os = "linux";
    arch = "amd64";
  };
  managerImage   = image "wazuh-manager"   "sha256:06ca4480512e471ed2bc250e2ff2a2193f5d552c81e2fd3640da711c74be5674" "sha256-x8kzztkyP6LuZlmPMP4FaX0kz/SGGvO9Lu6BlkrI83U=";
  indexerImage   = image "wazuh-indexer"   "sha256:2cc4b3cb408ed9a4dc0a4b46be18c08a9c555dd1c4a118e61e65d3550a87e87d" "sha256-KX1APDRvEu4PY4HWnMbVvI03ft2sR8756WN+izduY4c=";
  dashboardImage = image "wazuh-dashboard" "sha256:f557d06c3fbd06f26d2bde36cc4d41bb8edcafc2c5944b39399509bd18d07b7e" "sha256-DN1Wo5OYG/IykwXkV+ORnsSGyhmy1B0k4AcLJLwTMKM=";

  targetIps = map (t: t.ip) (builtins.attrValues (import ../targets.nix));
  # Syslog senders: pam-review (ai01), Boundary (hb01), Vault (hv01), the ops
  # agent (ag01), and the agent gate on each target.
  senders = [ net.ai01 net.boundaryWorker net.hv01 net.ag01 ] ++ targetIps;
  ossecConf = pkgs.writeText "ossec.conf" (builtins.replaceStrings
    [ "@AI01@" "@HB01@" "@HV01@" "@AG01@" "@TARGET_ALLOWED_IPS@" ]
    [ net.ai01 net.boundaryWorker net.hv01 net.ag01
      (lib.concatMapStringsSep "\n    " (ip: "<allowed-ips>${ip}</allowed-ips>") targetIps) ]
    (builtins.readFile "${wz}/ossec.conf"));

  python = pkgs.python3.withPackages (ps: [ ps.bcrypt ]);

  # All three share wz01's network; these names match the internal certs.
  common = [
    "--network=host"
    "--add-host=wazuh.indexer:127.0.0.1"
    "--add-host=wazuh.manager:127.0.0.1"
    "--add-host=wazuh.dashboard:127.0.0.1"
    "--security-opt" "seccomp=unconfined"
    "--ulimit" "nofile=65536:65536"
    # wz01 is a systemd-nspawn container. Its /sys/fs/cgroup is cgroup2 with
    # nsdelegate, which lets us mkdir in the delegated root but refuses to move
    # processes into a nested scope. So crun cannot place the container:
    #   systemd manager : error `creating` systemd unit `libpod-<id>.scope`: got `failed`
    #   cgroupfs manager: write to `/sys/fs/cgroup/libpod_parent/libpod-<id>/cgroup.procs`:
    #                     No such file or directory
    # Both podman cgroup managers fail, so the containers never started - Wazuh
    # had been crash-looping since the lab was first built. Letting podman skip
    # cgroup setup is what makes it run here. The trade-off is no cgroup limits
    # from podman; memory is still bounded where it matters by the indexer's
    # OPENSEARCH_JAVA_OPTS heap cap (-Xms1536m -Xmx1536m).
    "--cgroups=disabled"
  ];

  secretFiles = [ "wazuh-admin-password" "wazuh-kibanaserver-password" "wazuh-api-password" "wazuh-oidc-secret" ];

  curl = "${pkgs.curl}/bin/curl";
  jq = "${pkgs.jq}/bin/jq";
in
{
  networking.hostName = "wz01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];
  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  system.stateVersion = "26.05";

  # 80/443: Caddy (dashboard). 514: syslog, only from the known senders.
  # The indexer (9200), API (55000) and agent ports stay closed.
  networking.firewall = {
    allowedTCPPorts = [ 80 443 ];
    extraCommands = lib.concatMapStrings (ip: ''
      iptables -A nixos-fw -p tcp --dport 514 -s ${ip} -j nixos-fw-accept
    '') senders;
  };

  # overlay, not vfs. All three Wazuh images carry /dev/console as a char
  # device (5:1) in their layers. vfs builds a container's read-write layer by
  # *copying* the parent layer, so it re-creates that node with mknod - and
  # systemd units in this nspawn container are device-filtered, so the mknod is
  # refused:
  #   Error: creating container storage: creating read-write layer with ID
  #   "<id>": operation not permitted
  # with the real syscall being
  #   mknodat(".../vfs/dir/<layer>/dev/console", S_IFCHR|0600, makedev(5, 1))
  #     = -1 EPERM
  # It only reproduces inside a unit; the same command from a shell in this
  # container works, which is why it looked so arbitrary. DeviceAllow cannot
  # fix it: nspawn replaces /dev/console with a symlink, so systemd resolves
  # the rule to 0:0 and it matches nothing.
  # overlay *mounts* layers instead of copying them, so no device node is ever
  # created at layer-create time. This is what had Wazuh crash-looping since
  # the lab was first built (14372 logged failures, from 2026-11-08 onward).
  virtualisation.containers.storage.settings.storage.driver = "overlay";

  systemd.tmpfiles.rules = [
    "d ${W} 0755 root root -"
    "d ${certs} 0755 root root -"
    "d ${rendered} 0755 root root -"
    "d ${W}/indexer 0750 1000 1000 -"
  ];

  # --- Setup: certificates and secret-bearing configs ------------------------
  systemd.services.wazuh-certs = {
    description = "Create Wazuh internal TLS certificates (first boot)";
    path = [ pkgs.openssl pkgs.coreutils ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
    script = "${pkgs.bash}/bin/bash ${wz}/make_certs.sh ${certs}";
  };

  systemd.services.wazuh-config = {
    description = "Render Wazuh configs with secrets from hv01";
    after = [ "wazuh-certs.service" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "30min"; };
    script = ''
      for f in ${lib.concatStringsSep " " secretFiles}; do
        until [ -s ${handoff}/$f ]; do echo "Waiting for $f from hv01..."; sleep 10; done
      done
      ${python}/bin/python3 ${wz}/render_config.py ${wz} ${handoff} ${rendered}
      install -m 0444 ${stepRoot} ${certs}/lab-root-ca.pem
    '';
  };

  # --- The stack ----------------------------------------------------------------
  virtualisation.oci-containers.containers = {
    wazuh-indexer = {
      image = "wazuh/wazuh-indexer:${version}";
      imageFile = indexerImage;
      environment.OPENSEARCH_JAVA_OPTS = "-Xms1536m -Xmx1536m";
      volumes = [
        "${W}/indexer:/var/lib/wazuh-indexer"
        "${wz}/opensearch.yml:/usr/share/wazuh-indexer/config/opensearch.yml:ro"
        "${certs}/root-ca.pem:/usr/share/wazuh-indexer/config/certs/root-ca.pem:ro"
        "${certs}/lab-root-ca.pem:/usr/share/wazuh-indexer/config/certs/lab-root-ca.pem:ro"
        "${certs}/wazuh.indexer.pem:/usr/share/wazuh-indexer/config/certs/wazuh.indexer.pem:ro"
        "${certs}/wazuh.indexer-key.pem:/usr/share/wazuh-indexer/config/certs/wazuh.indexer.key:ro"
        "${certs}/admin.pem:/usr/share/wazuh-indexer/config/certs/admin.pem:ro"
        "${certs}/admin-key.pem:/usr/share/wazuh-indexer/config/certs/admin-key.pem:ro"
        "${rendered}/internal_users.yml:/usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml:ro"
        "${wz}/security-config.yml:/usr/share/wazuh-indexer/config/opensearch-security/config.yml:ro"
        "${wz}/roles_mapping.yml:/usr/share/wazuh-indexer/config/opensearch-security/roles_mapping.yml:ro"
      ];
      extraOptions = common;
    };

    wazuh-manager = {
      image = "wazuh/wazuh-manager:${version}";
      imageFile = managerImage;
      dependsOn = [ "wazuh-indexer" ];
      environment = {
        INDEXER_URL = "https://wazuh.indexer:9200";
        INDEXER_USERNAME = "admin";
        FILEBEAT_SSL_VERIFICATION_MODE = "full";
        SSL_CERTIFICATE_AUTHORITIES = "/etc/ssl/root-ca.pem";
        SSL_CERTIFICATE = "/etc/ssl/filebeat.pem";
        SSL_KEY = "/etc/ssl/filebeat.key";
        API_USERNAME = "wazuh-wui";
      };
      environmentFiles = [ "${rendered}/manager.env" ];
      volumes = [
        "${certs}/root-ca.pem:/etc/ssl/root-ca.pem:ro"
        "${certs}/wazuh.manager.pem:/etc/ssl/filebeat.pem:ro"
        "${certs}/wazuh.manager-key.pem:/etc/ssl/filebeat.key:ro"
        # The image copies /wazuh-config-mount/etc into /var/ossec/etc at start.
        "${ossecConf}:/wazuh-config-mount/etc/ossec.conf:ro"
        "${wz}/lab_rules.xml:/wazuh-config-mount/etc/rules/local_rules.xml:ro"
        # Without this the JSON decoder never fires for syslog-delivered events
        # and NONE of the 100xxx rules can match. See lab_decoders.xml.
        "${wz}/lab_decoders.xml:/wazuh-config-mount/etc/decoders/lab_decoders.xml:ro"
      ];
      extraOptions = common;
    };

    wazuh-dashboard = {
      image = "wazuh/wazuh-dashboard:${version}";
      imageFile = dashboardImage;
      dependsOn = [ "wazuh-indexer" "wazuh-manager" ];
      environment = {
        INDEXER_USERNAME = "admin";
        WAZUH_API_URL = "https://wazuh.manager";
        DASHBOARD_USERNAME = "kibanaserver";
        API_USERNAME = "wazuh-wui";
      };
      environmentFiles = [ "${rendered}/dashboard.env" ];
      volumes = [
        "${certs}/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem:ro"
        "${certs}/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem:ro"
        "${certs}/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem:ro"
        "${certs}/lab-root-ca.pem:/usr/share/wazuh-dashboard/certs/lab-root-ca.pem:ro"
        "${rendered}/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml:ro"
        "${rendered}/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml:ro"
      ];
      extraOptions = common;
    };
  };

  # All three Wazuh images carry /dev/console as a char device (5:1) inside
  # their layers, and podman's vfs driver re-creates it with mknod when it
  # builds the container's read-write layer. The per-unit device filter denies
  # that, so every start died with
  #   Error: creating container storage: creating read-write layer with ID
  #   "<id>": operation not permitted
  # and the real syscall underneath was
  #   mknodat(".../vfs/dir/<layer>/dev/console", S_IFCHR|0600, makedev(5, 1))
  #     = -1 EPERM
  # It only reproduces inside the unit: the same command run from a shell in
  # this container succeeds, because that shell is not under the unit's filter.
  # This is why Wazuh crash-looped from the day the lab was built.
  systemd.services.podman-wazuh-indexer = {
    after = [ "wazuh-certs.service" "wazuh-config.service" ];
    requires = [ "wazuh-certs.service" "wazuh-config.service" ];
    serviceConfig.DeviceAllow = [ "/dev/console rwm" ];
  };
  systemd.services.podman-wazuh-manager = {
    after = [ "wazuh-config.service" ];
    serviceConfig.DeviceAllow = [ "/dev/console rwm" ];
  };
  systemd.services.podman-wazuh-dashboard = {
    after = [ "wazuh-config.service" ];
    serviceConfig.DeviceAllow = [ "/dev/console rwm" ];
  };

  # --- Post-start configuration (idempotent, every boot) ------------------------

  # Push security config (users, OIDC, IT -> all_access) into the indexer.
  systemd.services.wazuh-security-apply = {
    description = "Apply Wazuh indexer security config";
    after = [ "podman-wazuh-indexer.service" ];
    requires = [ "podman-wazuh-indexer.service" ];
    wantedBy = [ "multi-user.target" ];
    path = [ pkgs.podman pkgs.curl ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "15min"; };
    script = ''
      until [ "$(curl -s -o /dev/null -w '%{http_code}' --cacert ${certs}/root-ca.pem https://127.0.0.1:9200)" = 401 ]; do
        echo "Waiting for the indexer..."; sleep 10
      done
      podman exec wazuh-indexer bash -c '
        export JAVA_HOME=/usr/share/wazuh-indexer/jdk
        C=/usr/share/wazuh-indexer/config
        bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
          -cd $C/opensearch-security/ -nhnv -icl -h 127.0.0.1 -p 9200 \
          -cacert $C/certs/root-ca.pem -cert $C/certs/admin.pem -key $C/certs/admin-key.pem'
    '';
  };

  # Wazuh API: users with backend role IT (via dashboard run_as) get administrator.
  systemd.services.wazuh-api-rbac = {
    description = "Map Keycloak group IT to the Wazuh API administrator role";
    after = [ "podman-wazuh-manager.service" ];
    requires = [ "podman-wazuh-manager.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "15min"; };
    script = ''
      set -uo pipefail
      pw=$(cat ${handoff}/wazuh-api-password)
      api=https://127.0.0.1:55000
      until token=$(${curl} -sfk -u "wazuh-wui:$pw" -X POST "$api/security/user/authenticate?raw=true"); do
        echo "Waiting for the Wazuh API..."; sleep 10
      done
      auth="Authorization: Bearer $token"
      id=$(${curl} -sfk -H "$auth" "$api/security/rules?search=lab-it-administrators" \
             | ${jq} -r '.data.affected_items[] | select(.name == "lab-it-administrators") | .id' | head -1)
      if [ -z "$id" ]; then
        id=$(${curl} -sfk -H "$auth" -H 'Content-Type: application/json' -X POST "$api/security/rules" \
               -d '{"name": "lab-it-administrators", "rule": {"FIND": {"backend_roles": "IT"}}}' \
             | ${jq} -r '.data.affected_items[0].id')
      fi
      # Role 1 is Wazuh's built-in "administrator".
      ${curl} -sfk -H "$auth" -X POST "$api/security/roles/1/rules?rule_ids=$id" >/dev/null || true
      echo "IT -> administrator (rule $id)"
    '';
  };

  # SOC saved searches + "PAM review (SOC)" dashboard.
  systemd.services.wazuh-saved-objects = {
    description = "Import SOC saved searches and dashboard";
    after = [ "podman-wazuh-dashboard.service" ];
    requires = [ "podman-wazuh-dashboard.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "45min"; };
    script = ''
      set -uo pipefail
      pw=$(cat ${handoff}/wazuh-admin-password)
      osd() { ${curl} -sk -u "admin:$pw" -H 'osd-xsrf: true' "$@"; }
      # The Wazuh app creates the wazuh-alerts-* index pattern once it's up.
      for _ in $(seq 1 240); do
        [ "$(osd -o /dev/null -w '%{http_code}' https://127.0.0.1:5601/api/saved_objects/index-pattern/wazuh-alerts-*)" = 200 ] && break
        sleep 10
      done
      osd -X POST "https://127.0.0.1:5601/api/saved_objects/_import?overwrite=true" \
        -F file=@${wz}/soc-saved-objects.ndjson | ${jq} -c '{success, successCount, errors}'
    '';
  };

  # A29: stop the indexer rejecting every Boundary alert.
  #
  # Wazuh's shipped wazuh-alerts index template maps data.data as a KEYWORD -
  # a flat string. A Boundary cloudevent carries its payload in a top-level
  # "data" object, so once lab_decoders.xml expands the JSON the alert has an
  # OBJECT at data.data and OpenSearch throws the whole document away:
  #
  #   mapper_parsing_exception: failed to parse field [data.data] of type
  #   [keyword]. Preview: '{request={details={worker_status={address=...
  #
  # The effect was invisible from the CLI and obvious on the dashboard:
  # analysisd decoded the event, the rule matched, alerts.json recorded it -
  # and then the indexer dropped it, so rules 100200-100210 fired 159 times
  # without ever appearing in Discover.
  #
  # Dropping data.data loses nothing: full_log already carries the complete
  # raw cloudevent verbatim (that is the tamper-evident trail the sink exists
  # for), and every lab rule selects on data.request_info.* instead.
  #
  # The processor is conditional, so alert types that legitimately put a
  # STRING in data.data - which is what the keyword mapping is there for -
  # are untouched. Only Map/List values, the ones that cannot be indexed, are
  # removed.
  systemd.services.wazuh-ingest-pipeline = {
    description = "Patch filebeat's alerts pipeline so object-valued data.data is indexable";
    after = [ "podman-wazuh-manager.service" "podman-wazuh-indexer.service" ];
    requires = [ "podman-wazuh-indexer.service" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; TimeoutStartSec = "30min"; };
    script = ''
      set -uo pipefail
      pw=$(cat ${handoff}/wazuh-admin-password)
      es() { ${curl} -sk -u "admin:$pw" -H 'Content-Type: application/json' "$@"; }
      base=https://127.0.0.1:9200/_ingest/pipeline

      # filebeat creates the pipeline on its first run; wait for it, and read
      # the name rather than hardcoding the filebeat version into it.
      name=""
      for _ in $(seq 1 180); do
        # "|| name=" matters: NixOS runs `script` under set -e, so while the
        # indexer is still starting curl exits 7 and the bare assignment would
        # kill the unit before this loop ever got to sleep. Same trap as A15.
        name=$(es "$base/filebeat-*-wazuh-alerts-pipeline" 2>/dev/null \
                 | ${jq} -r 'keys[0] // empty' 2>/dev/null) || name=""
        [ -n "$name" ] && break
        echo "Waiting for filebeat's alerts pipeline..."
        sleep 10
      done
      if [ -z "$name" ]; then
        echo "filebeat's alerts pipeline never appeared" >&2
        exit 1
      fi

      # Rebuild from whatever is there now, dropping any previous copy of our
      # processor first, so this is idempotent and survives filebeat
      # recreating the pipeline on a container restart.
      body=$(es "$base/$name" | ${jq} --arg n "$name" '
        .[$n]
        | .processors |= (
            map(select((.remove.field? // "") != "data.data"))
            + [{"remove": {
                  "field": "data.data",
                  "if": "ctx.data?.data instanceof Map || ctx.data?.data instanceof List",
                  "ignore_missing": true,
                  "ignore_failure": true
                }}]
          )
      ') || body=""
      if [ -z "$body" ] || [ "$body" = "null" ]; then
        echo "could not read pipeline $name" >&2
        exit 1
      fi

      es -X PUT "$base/$name" -d "$body" | ${jq} -c .
      echo "patched $name: object-valued data.data is now dropped at ingest"
    '';
  };

  # --- SOC entry point: https://wz01.lab.internal -------------------------------
  services.caddy = {
    enable = true;
    virtualHosts."wz01.lab.internal".extraConfig = ''
      tls {
        ca https://pki.lab.internal:9000/acme/acme/directory
        ca_root ${stepRoot}
      }
      reverse_proxy https://127.0.0.1:5601 {
        transport http {
          tls_trust_pool file ${certs}/root-ca.pem
          tls_server_name wazuh.dashboard
        }
      }
    '';
  };
  systemd.services.caddy.serviceConfig = {
    ReadOnlyPaths = [ "/var/lib/step-ca" certs ];
    ProtectSystem = "false";
  };
}
