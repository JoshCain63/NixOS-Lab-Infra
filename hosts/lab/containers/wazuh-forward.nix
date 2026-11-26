# Ship lines to Wazuh (wz01) over TCP syslog.
#
# Two sources:
#   file    = "/path/x.ndjson";  tail a JSON-lines file (remembers its position)
#   program = "agent-gate";      forward that program's journal messages
#
# The queue spills to disk, so lines written while wz01 is down are delivered
# when it comes back. Wazuh's JSON decoder picks up the payload after the
# syslog header.
{ tag, file ? null, program ? null }:
{ lib, ... }:

assert (file != null) != (program != null);

let
  forward = ''
    action(type="omfwd" target="wz01.lab.internal" port="514" protocol="tcp"
           template="RSYSLOG_ForwardFormat"
           queue.type="LinkedList" queue.filename="wazuh-forward"
           queue.maxDiskSpace="512m" queue.saveOnShutdown="on"
           action.resumeRetryCount="-1" action.resumeInterval="10")
  '';
in
{
  services.rsyslogd = {
    enable = true;
    extraConfig = ''
      global(workDirectory="/var/lib/rsyslog" maxMessageSize="64k")
    '' + lib.optionalString (file != null) ''
      # mode="polling": imfile's default inotify mode never delivered ag01's
      # ledger. Its state file sat at the offset it had on startup while the
      # file kept growing, so ops-agent events only reached Wazuh when
      # rsyslog was restarted. Polling every 2s is reliable here and the
      # volume is tiny.
      module(load="imfile" mode="polling" PollingInterval="2")
      input(type="imfile" File="${file}" Tag="${tag}:" ruleset="wazuh"
            reopenOnTruncate="on" freshStartTail="off")
      ruleset(name="wazuh") {
        ${forward}
      }
    '' + lib.optionalString (program != null) ''
      # Read the journal directly: the program can't tamper with what's sent.
      #
      # The $inputname test is not optional. NixOS's rsyslog also takes
      # /dev/log via imuxsock, so a message logged by the gate arrived twice
      # - once from imuxsock, once from imjournal - and both copies matched
      # this filter. Every agent-gate decision was forwarded and alerted on
      # twice, which double-counts in any SOC dashboard or frequency rule.
      module(load="imjournal" StateFile="imjournal.state")
      if $programname == "${program}" and $inputname == "imjournal" then {
        ${forward}
      }
    '';
  };

  systemd.tmpfiles.rules = [ "d /var/lib/rsyslog 0700 root root -" ];
}
