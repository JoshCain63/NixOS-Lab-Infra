# HashiCorp binaries pinned straight from releases.hashicorp.com.
# Hashes come from each release's published SHA256SUMS file.
#
# Using the official release zips (instead of nixpkgs' unfree source builds)
# means nothing has to compile locally and the containers don't need
# allowUnfree. To upgrade: bump the version and paste the new hash from
#   https://releases.hashicorp.com/<name>/<version>/<name>_<version>_SHA256SUMS
# (convert hex to SRI with: echo <hex> | xxd -r -p | base64).
{ pkgs }:

let
  zipUrl = name: version:
    "https://releases.hashicorp.com/${name}/${version}/${name}_${version}_linux_amd64.zip";

  release = { name, version, hash, dynamic ? false }:
    pkgs.stdenv.mkDerivation {
      pname = name;
      inherit version;
      src = pkgs.fetchurl { url = zipUrl name version; inherit hash; };
      nativeBuildInputs = [ pkgs.unzip ] ++ pkgs.lib.optional dynamic pkgs.autoPatchelfHook;
      dontUnpack = true;
      dontStrip = true;
      dontPatchELF = !dynamic;
      installPhase = ''
        mkdir -p $out/bin
        unzip -d $out/bin $src ${name}
        chmod +x $out/bin/${name}
      '';
      meta.mainProgram = name;
    };

  # Terraform providers laid out as a -plugin-dir, since the containers have
  # no internet access to reach the registry. `namespace`/`url` cover
  # providers that aren't published on releases.hashicorp.com.
  providers = [
    { type = "vault";    version = "5.13.0"; hash = "sha256-HftudNHH4itLO0d8q7NlcrJcPpdGt1AH5Ol6LFTqeyQ="; }
    { type = "boundary"; version = "1.7.0";  hash = "sha256-PTw5M6Mo6jxcJPhaVFby7yhm3ZQAWDXcGnYc+QXLAAw="; }
    {
      type = "keycloak"; version = "5.10.0"; namespace = "keycloak";
      hash = "sha256-qS1JVsxqKE5w7Ckxkys2ymrvzKuUDgpfV0FU20bfofE=";
      url = "https://github.com/keycloak/terraform-provider-keycloak/releases/download/v5.10.0/terraform-provider-keycloak_5.10.0_linux_amd64.zip";
    }
  ];

  providerUrl = p: p.url or (zipUrl "terraform-provider-${p.type}" p.version);
in
{
  vault = release {
    name = "vault"; version = "2.2.1";
    hash = "sha256-B5Q13o/xRr3sTNvjvnHWcu9OWeTfavDy26Zy5xviGmg=";
  };

  boundary = release {
    name = "boundary"; version = "0.21.3";
    hash = "sha256-GpSMFDuEnO26kRJ6oRFVxgBthAUSgqDZPz2JUltGDRI=";
  };

  terraform = release {
    name = "terraform"; version = "1.17.1";
    hash = "sha256-RjhigFjnGlUhKxxWNxLqwDuQISj0B0Dz3IF03xITUGE=";
  };

  # The only one of these that isn't statically linked.
  vault-ssh-helper = release {
    name = "vault-ssh-helper"; version = "0.2.4";
    hash = "sha256-H9dMz+TeE03MUndxyeqqL5V1aXXBG6/xNu7Nvla9Dh0=";
    dynamic = true;
  };

  terraformPlugins = pkgs.runCommand "terraform-plugins" { nativeBuildInputs = [ pkgs.unzip ]; } (
    pkgs.lib.concatMapStrings (p: ''
      d=$out/registry.terraform.io/${p.namespace or "hashicorp"}/${p.type}/${p.version}/linux_amd64
      mkdir -p $d
      unzip -d $d ${pkgs.fetchurl { url = providerUrl p; inherit (p) hash; }}
    '') providers
  );
}
