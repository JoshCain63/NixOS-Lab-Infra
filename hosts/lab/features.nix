# Lab feature switches, read by the host and container configs.
{
  # Run ai01's LLM on the GTX 980 (Vulkan) instead of the CPU, and load the
  # NVIDIA driver on the lab boot. Set to false to go back to CPU inference;
  # the "stable" boot entry never loads the NVIDIA driver either way.
  gpu = true;

  # pam-review (ai01) logs in as the governed AI agent svc-pam-review
  # (midPoint sponsor + expiry -> AD -> Keycloak -> Vault -> Boundary LDAP),
  # the same chain as the ops agent, instead of the Boundary-local
  # pam-reviewer account. On, it also retires pam-reviewer, its KV secret,
  # both AppRoles and hb01's rotation job. Needs the midPoint and AD steps in
  # docs/ai-pam.md ("Governed identity") done first: until svc-pam-review
  # exists in AD and hv01 has its ad-bind-password, vault-bootstrap fails.
  pamReviewNhi = true;
}
