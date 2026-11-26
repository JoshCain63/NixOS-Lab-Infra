# Lab addresses that firewall rules in more than one place depend on.
{
  # Vault: sends its audit log to Wazuh.
  hv01 = "192.168.100.17";

  # Boundary's worker (hb01) is the only source allowed to SSH to lt01-lt05.
  boundaryWorker = "192.168.100.18";

  # pam-review (ai01) is the only source allowed to send findings to Wazuh.
  ai01 = "192.168.100.19";
  wz01 = "192.168.100.20";

  # The ops agent: the only source allowed to reach ai01's Ollama.
  ag01 = "192.168.100.21";
}
