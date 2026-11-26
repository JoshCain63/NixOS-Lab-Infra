{ config, pkgs, ... }:

let
  midpointImage = pkgs.dockerTools.pullImage {
    imageName      = "evolveum/midpoint";
    imageDigest    = "sha256:cb407e65ca4db3d708abdad9c8dcd481b147760b1cf7ea75a58487fa2d2e80e6";
    hash           = "sha256-R86/qPAK6yv1CULGkQGFAu4JTcjGG5pDosVkMVW/zuk=";
    finalImageName = "evolveum/midpoint";
    finalImageTag  = "latest";
  };
in

{
  # Vault-rotated svc-midpoint password, mounted into midPoint at
  # /run/secrets/svc-midpoint for its Docker secrets provider.
  imports = [
    (import ./vault-agent.nix {
      account = "svc-midpoint";
      destination = "/run/midpoint-secrets/svc-midpoint";
    })
  ];

  # --- System & Networking ---
  system.stateVersion = "25.11";

  networking = {
    hostName = "mp01";
    defaultGateway = "192.168.100.1";
    nameservers = [ "192.168.100.1" ];
    firewall.allowedTCPPorts = [ 8080 ];
  };

  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';

  services.chrony.servers = [ "192.168.100.1" ];

  # --- Database Service ---
  services.postgresql = {
    enable = true;
    ensureDatabases = [ "midpoint" ];
    ensureUsers = [
      {
        name = "midpoint";
        ensureDBOwnership = true;
      }
    ];
    authentication = pkgs.lib.mkOverride 10 ''
      local all all              trust
      host  all all 127.0.0.1/32 trust
      host  all all ::1/128      trust
    '';
  };

  systemd.services.midpoint-pg-init = {
    description = "Initialize midpoint PostgreSQL schema and privileges";
    after = [ "postgresql.service" "network-online.target" ];
    requires = [ "postgresql.service" ];
    wants = [ "network-online.target" ];
    wantedBy = [ "multi-user.target" ];
    path = with pkgs; [ sudo podman gnugrep ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script =
      let
        psql = "${config.services.postgresql.package}/bin/psql";
        image = "evolveum/midpoint:latest";
        applySQL = sqlPath: ''
          (echo "SET search_path TO public;"; \
           podman run --rm --entrypoint cat ${image} ${sqlPath}) \
          | sudo -u postgres ${psql} -d midpoint
        '';
      in
      ''
        table_exists() {
          sudo -u postgres ${psql} -d midpoint -tAc \
            "SELECT EXISTS (SELECT FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = '$1');" \
          | grep -q t
        }

        sudo -u postgres ${psql} -d midpoint -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"
        sudo -u postgres ${psql} -d midpoint -c "CREATE EXTENSION IF NOT EXISTS intarray;"

        # Load from the Nix store — no internet access required.
        podman image exists ${image} || podman load -i ${midpointImage}

        if ! table_exists m_global_metadata; then
          echo "Applying main midPoint schema..."
          ${applySQL "/opt/midpoint/doc/config/sql/native/postgres.sql"}
        fi

        if ! table_exists qrtz_job_details; then
          echo "Applying Quartz schema..."
          ${applySQL "/opt/midpoint/doc/config/sql/native/postgres-quartz.sql"}
        fi

        if ! table_exists ma_audit_event; then
          echo "Applying audit schema..."
          ${applySQL "/opt/midpoint/doc/config/sql/native/postgres-audit.sql"}
        fi

        sudo -u postgres ${psql} -d midpoint -c "GRANT ALL PRIVILEGES ON SCHEMA public TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "ALTER TABLE m_shadow OWNER TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "ALTER TABLE m_shadow_default OWNER TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "ALTER TABLE m_shadow_partition_def OWNER TO midpoint;"
        sudo -u postgres ${psql} -d midpoint -c "ALTER TABLE m_shadow_ref_attribute OWNER TO midpoint;"
      '';
  };

  systemd.services.podman-midpoint = {
    after    = [ "midpoint-pg-init.service" ];
    requires = [ "midpoint-pg-init.service" ];
  };

  # midPoint is launched with -Djavax.net.ssl.trustStore=/opt/midpoint/var/keystore.jceks,
  # so the JVM-wide TLS trust anchors live in keystore.jceks (not the container's cacerts).
  # This imports the step-ca root into that keystore so LDAPS to AD validates correctly,
  # and restarts midpoint once so the JVM picks up the change. Idempotent on later boots.
  systemd.services.midpoint-truststore-init = {
    description = "Import step-ca root CA into midPoint's JCEKS truststore";
    after    = [ "podman-midpoint.service" ];
    wants    = [ "podman-midpoint.service" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };

    script = ''
      id=$(${pkgs.podman}/bin/podman ps --filter name=midpoint -q)

      # First boot can take a few minutes for midPoint to create midpoint.home
      for i in $(seq 1 90); do
        [ -f /opt/midpoint/var/keystore.jceks ] && break
        sleep 5
      done

      if [ ! -f /opt/midpoint/var/keystore.jceks ]; then
        echo "keystore.jceks never appeared, giving up"
        exit 1
      fi

      JH=$(${pkgs.podman}/bin/podman exec $id sh -c 'dirname $(dirname $(readlink -f $(which java)))')

      # Idempotent: skip if already trusted
      if ${pkgs.podman}/bin/podman exec $id "$JH/bin/keytool" -list \
          -keystore /opt/midpoint/var/keystore.jceks -storetype jceks \
          -storepass changeit -alias step-ca-root >/dev/null 2>&1; then
        echo "step-ca-root already present in keystore.jceks, nothing to do"
        exit 0
      fi

      echo "Importing step-ca root into midPoint keystore.jceks..."
      ${pkgs.podman}/bin/podman cp /var/lib/step-ca/root_ca.crt $id:/tmp/root_ca.crt
      ${pkgs.podman}/bin/podman exec $id "$JH/bin/keytool" -importcert \
        -keystore /opt/midpoint/var/keystore.jceks -storetype jceks \
        -storepass changeit -alias step-ca-root -trustcacerts \
        -file /tmp/root_ca.crt -noprompt

      echo "Restarting midpoint so the JVM reloads the truststore..."
      systemctl restart podman-midpoint
    '';
  };

  # --- Virtualization & Containers ---
  virtualisation.containers.storage.settings = {
    storage.driver = "vfs";
  };

  virtualisation.oci-containers.containers.midpoint = {
    image     = "evolveum/midpoint:latest";
    imageFile = midpointImage;
    ports = [ "8080:8080" ];

    volumes = [
      "/opt/midpoint/var:/opt/midpoint/var"
      "/srv/hr:/opt/midpoint/var/hr"
      "/run/midpoint-secrets:/run/secrets:ro"
    ];

    extraOptions = [
      "--network=host"
      "--security-opt"
      "seccomp=unconfined"
    ];

    environment = {
      MP_SET_midpoint_repository_database = "postgresql";
      MP_SET_midpoint_repository_jdbcUrl = "jdbc:postgresql://localhost:5432/midpoint";
      MP_SET_midpoint_repository_jdbcUsername = "midpoint";
      MP_SET_midpoint_repository_jdbcPassword = "midpoint";
      MP_SET_midpoint_repository_initializationFailTimeout = "60000";
      MP_SET_midpoint_repository_missingSchemaAction = "create";
    };
  };
}
