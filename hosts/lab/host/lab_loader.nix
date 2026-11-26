{ config, pkgs, ... }:

{
  imports = [
    ./networking.nix
    ./virtualization.nix
    ./pki.nix
    ./containers.nix
    ./linux-targets.nix
    ./hashicorp.nix
    ./gpu.nix
    ./agent.nix
  ];

  environment.systemPackages = [
    pkgs.step-cli
    pkgs.virt-viewer
    # scripts/tests/test_agent_gate.py shells out to `openssl` to build and
    # tamper with the ed25519 approval signatures; without it 9 of the 63
    # tests error out with FileNotFoundError.
    pkgs.openssl
  ];
}
