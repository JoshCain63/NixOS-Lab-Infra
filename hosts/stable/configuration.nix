{ config, pkgs, lib, ... }:

{
  imports = [
    ./hardware-configuration.nix
  ];

  # Bootloader
  boot.loader.grub.enable = true;
  boot.loader.grub.theme = null;
  boot.loader.grub.splashImage = null;
  boot.loader.grub.device = "/dev/sda";
  boot.loader.grub.useOSProber = false;
  boot.loader.grub.configurationLimit = 15;
  boot.loader.timeout = -1;
  boot.kernelParams = [ "pci=realloc" ];
  hardware.enableRedistributableFirmware = true;
  boot.kernelModules = [ "k10temp" ];
  boot.extraModprobeConfig = ''
    options rtw88_core disable_lps_deep=y
  '';

  networking.hostName = "nixos";
  networking.networkmanager.enable = true;

  time.timeZone = "America/Vancouver";
  i18n.defaultLocale = "en_CA.UTF-8";

  # Desktop
  services.xserver.enable = true;
  services.displayManager.sddm.enable = true;
  services.desktopManager.plasma6.enable = true;
  services.xserver.xkb = {
    layout = "us";
    variant = "";
  };

  services.printing.enable = true;

  services.pulseaudio.enable = false;
  security.rtkit.enable = true;
  services.pipewire = {
    enable = true;
    alsa.enable = true;
    alsa.support32Bit = true;
    pulse.enable = true;
  };

  users.users.joshu = {
    isNormalUser = true;
    group = "joshu";
    description = "josh";
    extraGroups = [ "networkmanager" "wheel" "libvirtd" ];
    packages = with pkgs; [
      kdePackages.kate
      vim git curl wget
      virt-manager qemu
      neofetch htop lm_sensors
    ];
  };
  users.groups.joshu = {};

  virtualisation.libvirtd.enable = true;
  programs.virt-manager.enable = true;
  programs.firefox.enable = true;
  nixpkgs.config.allowUnfree = true;

  nix.settings.experimental-features = [ "nix-command" "flakes" ];

  programs.bash = {
    interactiveShellInit = ''
      neofetch
    '';
  };

  programs.bash.shellAliases = {
    rebuild = "sudo nixos-rebuild boot --flake /etc/nixos#lab --profile-name IAM_Lab && sudo nixos-rebuild switch --flake /etc/nixos#stable";
  };

  fileSystems."/mnt/wd_blue" = {
    device = "/dev/disk/by-label/WD_Blue";
    fsType = "ext4";
    options = [ "defaults" "nofail" ];
  };

  services.openssh.enable = true;

  system.stateVersion = "25.11";
}
