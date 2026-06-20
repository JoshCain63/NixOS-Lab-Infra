{ config, pkgs, ... }:

{
  virtualisation.libvirtd.enable = true;
  virtualisation.libvirtd.allowedBridges = [ "br-lab" ];
  programs.virt-manager.enable = true;
  virtualisation.docker.enable = true;

  users.groups.libvirtd.members = [ "joshu" ];
}
