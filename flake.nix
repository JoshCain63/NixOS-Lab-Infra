{
  description = "IAM Homelab";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { self, nixpkgs }:
  let
    system = "x86_64-linux";
    lib = nixpkgs.lib;
  in {
    nixosConfigurations = {
      stable = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./hosts/stable/configuration.nix ];
      };

      lab = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          ./hosts/stable/configuration.nix
          ./hosts/lab/host/lab_loader.nix
          {
            networking.hostName = lib.mkForce "nixos-lab";
            nix.settings.experimental-features = [ "nix-command" "flakes" ];
            nix.gc = {
              automatic = true;
              dates = "weekly";
              options = "--delete-older-than 7d";
            };
          }
        ];
      };
    };
  };
}
