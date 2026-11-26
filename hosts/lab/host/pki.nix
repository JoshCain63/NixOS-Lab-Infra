{ config, pkgs, lib, ... }:

{
  # Create a real step-ca user so ownership is stable across boots.
  users.users.step-ca = {
    isSystemUser = true;
    group = "step-ca";
    home = "/var/lib/step-ca";
  };
  users.groups.step-ca = {};

  # Fix ownership and permissions before step-ca starts.
  systemd.services.step-ca.serviceConfig = {
    DynamicUser  = lib.mkForce false;
    User         = lib.mkForce "step-ca";
    Group        = lib.mkForce "step-ca";
    ExecStartPre = [
      "+${pkgs.coreutils}/bin/chown -R step-ca:step-ca /var/lib/step-ca"
      "+${pkgs.coreutils}/bin/chmod 644 /var/lib/step-ca/certs/root_ca.crt"
    ];
  };

  services.step-ca = {
    enable = true;
    address = "0.0.0.0";
    port = 9000;
    intermediatePasswordFile = "/var/lib/step-ca/secrets/password";
    settings = {
      root = "/var/lib/step-ca/certs/root_ca.crt";
      crt = "/var/lib/step-ca/certs/intermediate_ca.crt";
      key = "/var/lib/step-ca/secrets/intermediate_ca_key";
      dnsNames = [ "pki.lab.internal" ];
      logger = { format = "text"; };
      db = {
        type = "badgerv2";
        dataSource = "/var/lib/step-ca/db";
        badgerFileLoadingMode = "";
      };
      authority = {
        provisioners = [
          {
            type = "JWK";
            name = "admin@lab.internal";
            # win-srv01's LDAPS certificate is issued by hand: Windows has
            # no ACME client here, so step-ca's 24-hour default silently
            # expired it (issued 2026-06-13, dead 2026-06-14) and left
            # Vault's LDAP engine unable to verify LDAPS. Allow long-lived
            # certificates on this provisioner; containers still use ACME.
            claims = {
              minTLSCertDuration     = "5m";
              defaultTLSCertDuration = "2160h";
              maxTLSCertDuration     = "8760h";
            };
            key = {
              use = "sig";
              kty = "EC";
              kid = "SyJo8H0xY5teBItChgA65YPby0lKbGrFjgDkSOAMWB0";
              crv = "P-256";
              alg = "ES256";
              x = "wqqkvRfNdtnQtO2EhdOulPPdEPY6pn3FKzyxXqdQzdo";
              y = "NCFTXFRDoKc_JqKshuA6DWt_zwd9RyOprez2WrJ09U4";
            };
            encryptedKey = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjYwMDAwMCwicDJzIjoiVVAyQ2ozSFlrTzU3Z3BRNnUwdnRTQSJ9.tr0KBc13z4BVsUhKSlq180M3h-nXtOs2KFG9Bawm_eD77feAnfCvRw.tES6DjvRKwMfW4Sh.LhQtp1EAKSE_tWUmScJKHqWuGW54rVDdKgIwbNGjTasT5fhcoUc2JkPvyA7EQ8do0pEawkvr5Xjpi7lCy9-eYl3xHBXm0r9pulMdIOOVG4HWpO4Udh9hfGVKfiv3Xa-VPEt3_QH_isHmIIcXnf_oAYLTrLvldzV8D-ekJCNTUSx4nmhc169Ag0fmbyNDFlGo-MDONOZKZTgmShL8W0OGNtSi3AM_30drW_8Mj-NNDKuJgRJOJvVoi-ySC8m1RLuDWerXKiYitnoFOYAjLicN5cSijtrFR_yF6LNVDkezyFN_3zTYtiCz5M85FQvcNJrF3EDi7Zdsv5OKsftRt_o.OasKKfbLCEXw0LYeHuU3Hg";
          }
          {
            type = "ACME";
            name = "acme";
          }
        ];
      };
      tls = {
        minVersion = 1.2;
        maxVersion = 1.3;
        cipherSuites = [
          "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
          "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        ];
      };
    };
  };
}
