{ config, pkgs, lib, ... }:

# ---------------------------------------------------------------------------
# Entra study lab (SC-300)
#
# Declaratively defines:
#   - one isolated, NAT'd libvirt network: 192.168.200.0/24
#       * DC  (entra-dc)    : 192.168.200.10  — Windows Server 2022 (AD DS + DNS)
#       * Win11 (entra-win11): 192.168.200.20  — Windows 11 (hybrid-joined client)
#   - firewall/NAT rules (entra_networking.nix):
#       * VMs may only reach the internet on 80/443
#       * intra-entra AD traffic is unrestricted
#       * VMs cannot reach the host's lab bridge or any other subnet
#
# What this DOES automate (every `nixos-rebuild boot/switch` re-applies it,
# idempotently, via a oneshot systemd service):
#   - creates/updates the libvirt network definition
#   - creates the two qcow2 disks if they don't already exist
#   - defines (or re-defines) the two libvirt domains with the right
#     firmware/TPM/chipset so Windows 11 setup doesn't complain
#
# What this DOES NOT automate (inherently interactive / lives inside the
# guest OS, not in libvirt):
#   - the actual Windows Server / Windows 11 installation
#   - static IP + DNS configuration inside each guest
#   - promoting the server to a Domain Controller, installing DNS
#   - domain-joining the Windows 11 client
#   - installing/configuring the Entra Connect or Cloud Sync agent
#
# See the accompanying study-plan notes for the manual steps and the
# order to do them in.
# ---------------------------------------------------------------------------

let
  ## ---- tunables -----------------------------------------------------------
  netName       = "entra-lab";
  netUuid       = "40325b1e-236f-4ec8-8aa0-202eb7e5600c";
  bridgeName    = "virbr-entra";
  subnetPrefix  = "192.168.200";       # requirement: everything on .200.0/24
  dcIp          = "${subnetPrefix}.10";
  win11Ip       = "${subnetPrefix}.20";
  dhcpStart     = "${subnetPrefix}.100";
  dhcpEnd       = "${subnetPrefix}.200";

  dcMac         = "52:54:00:20:10:01";
  win11Mac      = "52:54:00:20:10:02";

  vmStorageDir  = "/mnt/wd_blue/VMs/entra";
  dcDiskFile    = "${vmStorageDir}/dc.qcow2";
  win11DiskFile = "${vmStorageDir}/win11.qcow2";
  dcDiskSize    = "80G";
  win11DiskSize = "80G";

  winServerIso  = "/mnt/wd_blue/VMs/Windows Server 2022 EVAL.iso";
  win11Iso      = "/mnt/wd_blue/VMs/Windows 11 EVAL.iso";

  dcName        = "entra-dc";
  dcUuid        = "b7c13a05-79a8-4028-8698-f082b51f5cf8";
  dcMemoryGiB   = 6;
  dcVcpu        = 2;

  win11Name     = "entra-win11";
  win11Uuid     = "9b822d5b-4df8-42c4-9523-819e63c94994";
  win11MemoryGiB = 8;
  win11Vcpu     = 2;

  ## ---- libvirt network XML -------------------------------------------------
  # NAT forwarding gives both VMs outbound internet access (required for
  # Cloud Sync / Connect to reach Entra ID). This is NAT only at the edge
  # of 192.168.200.0/24 going out to the internet - traffic *between* the
  # two VMs (LDAP/Kerberos/GC) stays on the flat internal subnet and is
  # never translated, which is the distinction that matters: Entra Cloud
  # Sync's "not supported over NAT" caveat is about NAT'ing the AD traffic
  # itself, not about a NAT'd internet egress path (every real-world AD
  # site behind a firewall/NAT router uses exactly this shape).
  #
  # Outbound ports are further restricted to 80/443 by entra_networking.nix.
  networkXml = pkgs.writeText "entra-lab-network.xml" ''
    <network>
      <name>${netName}</name>
      <uuid>${netUuid}</uuid>
      <forward mode='nat'/>
      <bridge name='${bridgeName}' stp='on' delay='0'/>
      <ip address='${subnetPrefix}.1' netmask='255.255.255.0'>
        <dhcp>
          <range start='${dhcpStart}' end='${dhcpEnd}'/>
          <host mac='${dcMac}' ip='${dcIp}'/>
          <host mac='${win11Mac}' ip='${win11Ip}'/>
        </dhcp>
      </ip>
    </network>
  '';

  ## ---- Windows Server 2022 domain (plain BIOS/i440fx - no TPM needed) -----
  dcXml = pkgs.writeText "entra-dc.xml" ''
    <domain type='kvm'>
      <name>${dcName}</name>
      <uuid>${dcUuid}</uuid>
      <memory unit='GiB'>${toString dcMemoryGiB}</memory>
      <currentMemory unit='GiB'>${toString dcMemoryGiB}</currentMemory>
      <vcpu>${toString dcVcpu}</vcpu>
      <os>
        <type arch='x86_64' machine='pc'>hvm</type>
        <boot dev='cdrom'/>
        <boot dev='hd'/>
      </os>
      <features>
        <acpi/>
        <apic/>
        <hyperv>
          <relaxed state='on'/>
          <vapic state='on'/>
          <spinlocks state='on' retries='8191'/>
        </hyperv>
      </features>
      <cpu mode='host-passthrough'/>
      <clock offset='localtime'>
        <timer name='hypervclock' present='yes'/>
      </clock>
      <on_poweroff>destroy</on_poweroff>
      <on_reboot>restart</on_reboot>
      <on_crash>destroy</on_crash>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='${dcDiskFile}'/>
          <target dev='sda' bus='sata'/>
        </disk>
        <disk type='file' device='cdrom'>
          <driver name='qemu' type='raw'/>
          <source file='${winServerIso}'/>
          <target dev='sdb' bus='sata'/>
          <readonly/>
        </disk>
        <interface type='network'>
          <source network='${netName}'/>
          <mac address='${dcMac}'/>
          <model type='e1000e'/>
        </interface>
        <graphics type='spice' autoport='yes'/>
        <video><model type='qxl'/></video>
        <channel type='spicevmc'>
          <target type='virtio' name='com.redhat.spice.0'/>
        </channel>
        <channel type='unix'>
          <target type='virtio' name='org.qemu.guest_agent.0'/>
        </channel>
      </devices>
    </domain>
  '';

  ## ---- Windows 11 domain (Q35 + OVMF/UEFI + emulated TPM 2.0) --------------
  # firmware='efi' with secure-boot uses libvirt's firmware auto-selection
  # against the descriptor JSON NixOS registers for the qemu package.
  # enrolled-keys is explicitly disabled — eval ISOs don't need MS keys
  # pre-loaded in the VARS file; OVMF setup mode (Secure Boot capable but
  # no keys enrolled) satisfies the Windows 11 installer check, and the
  # plain secure-boot descriptor is what the bundled QEMU firmware ships.
  win11Xml = pkgs.writeText "entra-win11.xml" ''
    <domain type='kvm'>
      <name>${win11Name}</name>
      <uuid>${win11Uuid}</uuid>
      <memory unit='GiB'>${toString win11MemoryGiB}</memory>
      <currentMemory unit='GiB'>${toString win11MemoryGiB}</currentMemory>
      <vcpu>${toString win11Vcpu}</vcpu>
      <os firmware='efi'>
        <type arch='x86_64' machine='q35'>hvm</type>
        <firmware>
          <feature enabled='yes' name='secure-boot'/>
          <feature enabled='no' name='enrolled-keys'/>
        </firmware>
        <boot dev='cdrom'/>
        <boot dev='hd'/>
      </os>
      <features>
        <acpi/>
        <apic/>
        <smm state='on'/>
        <hyperv>
          <relaxed state='on'/>
          <vapic state='on'/>
          <spinlocks state='on' retries='8191'/>
        </hyperv>
      </features>
      <cpu mode='host-passthrough'/>
      <clock offset='localtime'>
        <timer name='hypervclock' present='yes'/>
      </clock>
      <on_poweroff>destroy</on_poweroff>
      <on_reboot>restart</on_reboot>
      <on_crash>destroy</on_crash>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='${win11DiskFile}'/>
          <target dev='sda' bus='sata'/>
        </disk>
        <disk type='file' device='cdrom'>
          <driver name='qemu' type='raw'/>
          <source file='${win11Iso}'/>
          <target dev='sdb' bus='sata'/>
          <readonly/>
        </disk>
        <tpm model='tpm-crb'>
          <backend type='emulator' version='2.0'/>
        </tpm>
        <interface type='network'>
          <source network='${netName}'/>
          <mac address='${win11Mac}'/>
          <model type='e1000e'/>
        </interface>
        <graphics type='spice' autoport='yes'/>
        <video><model type='qxl'/></video>
        <channel type='spicevmc'>
          <target type='virtio' name='com.redhat.spice.0'/>
        </channel>
        <channel type='unix'>
          <target type='virtio' name='org.qemu.guest_agent.0'/>
        </channel>
      </devices>
    </domain>
  '';

in
{
  imports = [
    ./entra_networking.nix
    ./entra_waydroid.nix
  ];

  environment.systemPackages = [
    pkgs.virt-viewer   # SPICE console access to the Windows VMs
  ];

  # Emulated TPM 2.0 — required for Windows 11 guest.
  # NixOS 25.11 removed the libvirtd.qemu.ovmf submodule; all OVMF images
  # (including the secure-boot + enrolled-keys variants Win11 needs) are now
  # bundled automatically with QEMU, so no explicit override is required.
  virtualisation.libvirtd.qemu.swtpm.enable = true;

  # Polkit is required by the libvirtd module; Plasma already pulls
  # this in, stated here explicitly so this module doesn't silently
  # depend on that.
  security.polkit.enable = true;

  systemd.services.entra-lab-provision = {
    description = "Define the Entra study-lab libvirt network and VMs";
    after = [ "libvirtd.service" ];
    requires = [ "libvirtd.service" ];
    wantedBy = [ "multi-user.target" ];
    path = [ pkgs.libvirt pkgs.qemu_kvm ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      set -eu

      # --- network (idempotent: define+autostart+start; ignore "already active") ---
      virsh net-define "${networkXml}"
      virsh net-autostart "${netName}"
      virsh net-start "${netName}" 2>/dev/null || true

      # --- disks (create only if missing; never touches existing data) ---
      mkdir -p "${vmStorageDir}"
      [ -f "${dcDiskFile}" ]    || qemu-img create -f qcow2 "${dcDiskFile}"    ${dcDiskSize}
      [ -f "${win11DiskFile}" ] || qemu-img create -f qcow2 "${win11DiskFile}" ${win11DiskSize}

      # --- domains (re-define is safe: updates persistent XML only,
      #     does not touch/restart an already-running VM) ---
      virsh define "${dcXml}"
      virsh define "${win11Xml}"
    '';
  };
}
