{ config, pkgs, lib, ... }:

# ---------------------------------------------------------------------------
# Waydroid — Android container for Entra ID / Microsoft auth testing
#
# This module is imported only by entra_loader.nix, so Waydroid is never
# present when booted into the `stable` or `lab` profiles.
#
# Storage lives alongside the Windows VMs on the WD Blue:
#   /mnt/wd_blue/VMs/entra/waydroid/   ← bind-mounted to /var/lib/waydroid
#
# ── First-time setup (manual, run once after first boot) ──────────────────
#
#   1. Initialise with the GApps image (downloads ~1 GB):
#        sudo waydroid init -s GAPPS -f
#
#   2. Start the container and open the UI:
#        waydroid session start
#        waydroid-launch            ← wrapper below; handles NVIDIA SW-GL
#
#   3. Certify the device with Google Play (required for the Play Store):
#        a. Open a shell inside the container:
#             sudo waydroid shell
#        b. Get the Android ID:
#             sqlite3 /data/data/com.google.android.gsf/databases/gservices.db \
#               "select * from main where name = 'android_id';"
#        c. Register that ID at https://www.google.com/android/uncertified/
#        d. Reboot the session (~10 min propagation):
#             waydroid session stop && waydroid session start
#
# ── NVIDIA note ───────────────────────────────────────────────────────────
#
# Proprietary NVIDIA drivers don't expose a DRI render node that Waydroid
# can negotiate a buffer-sharing protocol with.  The `waydroid-launch`
# wrapper forces Mesa's software rasteriser (llvmpipe) on the *host* side
# so the Android session renders without touching the GPU at all.
# llvmpipe is quick enough for Microsoft auth flows and web-based SSO.
#
# If a future NVIDIA driver adds full GBM / dmabuf support you can test
# without SW-GL by calling `waydroid show-full-ui` directly.
# ---------------------------------------------------------------------------

let
  waydroidDataDir = "/mnt/wd_blue/VMs/entra/waydroid";

  # Shell wrapper: open the full Android UI with Mesa software rendering.
  # Passes any extra arguments straight through to `waydroid show-full-ui`
  # (e.g. `waydroid-launch` is equivalent to `waydroid show-full-ui`).
  waydroidLaunch = pkgs.writeShellScriptBin "waydroid-launch" ''
    exec env \
      LIBGL_ALWAYS_SOFTWARE=1 \
      MESA_LOADER_DRIVER_OVERRIDE=llvmpipe \
      ${pkgs.waydroid}/bin/waydroid show-full-ui "$@"
  '';

in
{
  # ── Android container ────────────────────────────────────────────────────
  # Enables the binder_linux kernel module, creates /var/lib/waydroid, and
  # registers the waydroid-container.service systemd unit.
  virtualisation.waydroid.enable = true;

  # ── Storage: bind /var/lib/waydroid → WD Blue VM directory ──────────────
  # The directory is created by tmpfiles before the first mount attempt.
  # The bind mount carries a soft dependency on /mnt/wd_blue so it is
  # attempted only after the drive is available; nofail means the system
  # still boots cleanly if the drive is absent (Waydroid would fall back
  # to local storage and need re-initialising when the drive returns).

  systemd.tmpfiles.rules = [
    "d ${waydroidDataDir} 0755 root root -"
  ];

  fileSystems."/var/lib/waydroid" = {
    device  = waydroidDataDir;
    fsType  = "none";
    options = [
      "bind"
      "nofail"
      "x-systemd.requires-mounts-for=/mnt/wd_blue"
    ];
  };

  # Start the container service only after the bind mount is in place.
  # `wants` (not `requires`) keeps Waydroid startable even if the WD Blue
  # is absent — mirrors how the lab VMs handle a missing disk.
  systemd.services.waydroid-container = {
    after = [ "var-lib-waydroid.mount" ];
    wants = [ "var-lib-waydroid.mount" ];
  };

  # ── Packages ─────────────────────────────────────────────────────────────
  environment.systemPackages = [
    pkgs.waydroid      # waydroid session / app / shell / show-full-ui
    waydroidLaunch     # waydroid-launch: full Android UI with SW-GL for NVIDIA
    pkgs.wl-clipboard  # wl-copy / wl-paste: clipboard bridge to the Android session
  ];
}
