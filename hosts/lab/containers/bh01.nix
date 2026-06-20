{ config, pkgs, ... }:

let
  bloodhoundImage = pkgs.dockerTools.pullImage {
    imageName      = "specterops/bloodhound";
    imageDigest    = "sha256:32dfb5f178737d7a82b3c09309240c92feee3b92e486b3dbaabef49e1b03af0c";
    hash           = "sha256-lioVVtyE/LYs225JIiyVKpJpMqeS6ZcjejW7jYrt6vc=";
    finalImageName = "specterops/bloodhound";
    finalImageTag  = "latest";
  };
in

{
  networking.hostName = "bh01";
  networking.defaultGateway = "192.168.100.1";
  networking.nameservers = [ "192.168.100.1" ];

  networking.resolvconf.enable = false;
  environment.etc."resolv.conf".text = ''
    nameserver 192.168.100.1
    search lab.internal
  '';
  networking.firewall.allowedTCPPorts = [ 7474 7687 ];
  system.stateVersion = "25.11";

  virtualisation.containers.storage.settings = {
    storage = {
      driver = "vfs";
    };
  };

  virtualisation.oci-containers.containers.bloodhound = {
    image     = "specterops/bloodhound:latest";
    imageFile = bloodhoundImage;
    ports     = [ "7474:7474" "7687:7687" ];
    extraOptions = [ "--security-opt" "seccomp=unconfined" ];
  };

  services.chrony.servers = [ "192.168.100.1" ];
}
