{ config, pkgs, ... }:

{
  imports = [
    ./networking.nix
    ./virtualization.nix
    ./pki.nix
    ./containers.nix
  ];

  environment.systemPackages = [
    pkgs.step-cli
    pkgs.virt-viewer
  ];
}
