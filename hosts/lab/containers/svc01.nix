{ config, pkgs, ... }:

let
  whoamiPy = pkgs.writeText "whoami.py" ''
    import http.server

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            info = (
                "Method: " + self.command + "\n" +
                "Path:   " + self.path    + "\n" +
                "Client: " + self.client_address[0] + "\n\n"
            )
            hdrs = "\n".join(k + ": " + v for k, v in self.headers.items())
            body = (info + hdrs + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    http.server.HTTPServer(("127.0.0.1", 2001), Handler).serve_forever()
  '';
in

{
  networking.hostName = "svc01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.10" ];
  networking.firewall.allowedTCPPorts = [ 80 443 ];
  system.stateVersion = "25.11";

  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.10
    search lab.internal
  '';

  systemd.services.whoami = {
    description = "HTTP header echo service";
    wantedBy = [ "multi-user.target" ];
    after    = [ "network.target" ];
    serviceConfig = {
      ExecStart = "${pkgs.python3}/bin/python3 ${whoamiPy}";
      Restart   = "on-failure";
      DynamicUser = true;
    };
  };

  services.redis.servers.oauth2-proxy = {
    enable = true;
    bind   = "127.0.0.1";
    port   = 6379;
  };

  services.oauth2-proxy = {
    enable   = true;
    provider = "keycloak-oidc";

    clientID     = "oauth2-proxy";
    # 26.05 only accepts secrets as files. These are lab-only values (they end
    # up in the world-readable Nix store); replace them before reusing anywhere.
    clientSecretFile = pkgs.writeText "oauth2-proxy-client-secret" "fYLAry2O6YgHZuR211cpglKYNmYQo8Qt";
    cookie.secretFile = pkgs.writeText "oauth2-proxy-cookie-secret" "5UHhOGxJtkOwWXI2qovLaRcNJQCSGCcj1okT2s4ggeA=";

    email.domains = [ "*" ];
    httpAddress   = "127.0.0.1:4180";
    upstream      = [ "http://127.0.0.1:2001" ];

    extraConfig = {
      oidc-issuer-url  = "http://idp01.lab.internal/realms/lab";
      oidc-email-claim = "preferred_username";
      oidc-jwks-url    = "http://idp01.lab.internal/realms/lab/protocol/openid-connect/certs";

      redirect-url = "https://whoami.lab.internal/oauth2/callback";

      reverse-proxy        = true;
      skip-provider-button = true;

      cookie-secure   = true;
      # SameSite=None is required here.  Keycloak returns the auth code via
      # response_mode=form_post (a cross-origin POST to /oauth2/callback).
      # SameSite=Lax blocks cookies on cross-site POSTs, so the _oauth2_proxy_csrf
      # cookie never arrives at the callback handler → 403 CSRF failure.
      # SameSite=None + Secure=true is valid and supported by all modern browsers.
      cookie-samesite = "none";
      cookie-domain   = ".lab.internal";
      # No explicit expire → session cookie.  The browser drops it on close,
      # which prevents a stale _oauth2_proxy cookie (pointing at a dead Redis
      # session after front-channel logout) from persisting and confusing the
      # next login flow.  Remove this comment and restore cookie-expire if you
      # need sessions to survive a browser restart.
      cookie-refresh  = "4m";

      session-store-type   = "redis";
      redis-connection-url = "redis://127.0.0.1:6379";

      whitelist-domain = ".lab.internal";

      set-xauthrequest  = true;
      pass-access-token = true;
      pass-user-headers = true;

      # Policy: only users with department=Engineering in Active Directory may access this service.
      # The department attribute is mapped to the groups claim in Keycloak.
      # TODO Make this policy driven by Terraform identity as code
      allowed-group = "Engineering";
    };
  };

  systemd.services.oauth2-proxy = {
    after    = [ "redis-oauth2-proxy.service" "network-online.target" ];
    wants    = [ "redis-oauth2-proxy.service" ];
    requires = [ "network-online.target" ];
    serviceConfig = {
      RestartSec      = "10s";
      StartLimitBurst = 0;
    };
  };

  systemd.services.caddy.serviceConfig = {
    ReadOnlyPaths = [ "/var/lib/step-ca" ];
    ProtectSystem = "false";
  };

  services.caddy = {
    enable = true;
    virtualHosts."whoami.lab.internal" = {
      extraConfig = ''
        tls {
          ca https://pki.lab.internal:9000/acme/acme/directory
          ca_root /var/lib/step-ca/root_ca.crt
        }
        reverse_proxy 127.0.0.1:4180 {
          # Explicitly forward the scheme and host so oauth2-proxy builds
          # correct redirect URIs and trusts the TLS context from Caddy.
          header_up X-Forwarded-Proto https
          header_up X-Forwarded-Host  {host}
        }
      '';
    };
  };

  services.chrony.servers = [ "192.168.100.1" ];
}
