# GTX 980 (Maxwell) for ai01's LLM. Lab boot only; switch: ../features.nix.
#
# - Driver: Maxwell needs NVIDIA's 580 branch (the last to support it; newer
#   branches dropped it) and the proprietary kernel module (the open module
#   is Turing and newer only). The desktop runs on it too.
# - Inference uses Vulkan, not CUDA: CUDA 13 dropped Maxwell, and nixpkgs'
#   CUDA builds don't target it, so ollama-cuda would be a long unfree local
#   build. ollama-vulkan comes from the binary cache and uses this driver's
#   Vulkan support.
# - ai01 gets the GPU device nodes and the host's driver libraries, so the
#   container's Vulkan always matches the host kernel driver.
{ config, lib, ... }:

let
  gpu = (import ../features.nix).gpu;
  devices = [ "/dev/nvidia0" "/dev/nvidiactl" "/dev/nvidia-modeset" ];
in
lib.mkIf gpu {
  services.xserver.videoDrivers = [ "nvidia" ];
  hardware.graphics.enable = true;
  hardware.nvidia = {
    package = config.boot.kernelPackages.nvidiaPackages.legacy_580;
    open = false;
    modesetting.enable = true;
    nvidiaSettings = true;
  };

  containers.ai01 = {
    allowedDevices = map (node: { inherit node; modifier = "rw"; }) devices;
    bindMounts = lib.genAttrs devices (dev: { hostPath = dev; isReadOnly = false; })
      // {
        # Host userspace driver (incl. the Vulkan ICD), matching the kernel module.
        "/run/opengl-driver" = { hostPath = "/run/opengl-driver"; isReadOnly = true; };
      };
  };

  # The nodes appear once udev has handled the driver; a missing bind source
  # would stop ai01 from starting, so wait briefly for them.
  systemd.services."container@ai01" = {
    after = [ "systemd-udev-settle.service" ];
    wants = [ "systemd-udev-settle.service" ];
    preStart = lib.mkBefore ''
      for _ in $(seq 1 30); do
        [ -e /dev/nvidia0 ] && [ -e /dev/nvidiactl ] && [ -e /dev/nvidia-modeset ] && break
        sleep 1
      done
    '';
  };
}
