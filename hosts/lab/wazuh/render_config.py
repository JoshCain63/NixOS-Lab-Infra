"""Render Wazuh configs that need secrets, at boot on wz01.

Templates come from the Nix store (no secrets); passwords and the OIDC client
secret come from hv01's hand-off directory. Output goes to /var/lib/wazuh/config.

    python3 render_config.py <templates_dir> <handoff_dir> <out_dir>
"""

import os
import re
import sys

import bcrypt

UID = GID = 1000  # wazuh-indexer / wazuh-dashboard users inside the images


def secret(handoff, name):
    with open(os.path.join(handoff, name)) as f:
        return f.read().strip()


def write(path, text, mode, owner=None):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    if owner:
        os.chown(tmp, *owner)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def bcrypt_hash(password):
    # $2a$ prefix: what the OpenSearch security plugin's own hash.sh produces.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12, prefix=b"2a")).decode()


PLACEHOLDER = re.compile(r"@[A-Z][A-Z0-9_]*@")


def fill(template, values):
    for key, value in values.items():
        template = template.replace(f"@{key}@", value)
    left = PLACEHOLDER.findall(template)
    if left:
        sys.exit(f"unfilled placeholders: {', '.join(sorted(set(left)))}")
    return template


def main(templates, handoff, out):
    os.makedirs(out, exist_ok=True)
    admin = secret(handoff, "wazuh-admin-password")
    kibanaserver = secret(handoff, "wazuh-kibanaserver-password")
    api = secret(handoff, "wazuh-api-password")
    oidc = secret(handoff, "wazuh-oidc-secret")

    def tmpl(name):
        with open(os.path.join(templates, name)) as f:
            return f.read()

    write(os.path.join(out, "internal_users.yml"),
          fill(tmpl("internal_users.yml.tmpl"),
               {"ADMIN_HASH": bcrypt_hash(admin), "KIBANASERVER_HASH": bcrypt_hash(kibanaserver)}),
          0o640, (UID, GID))
    write(os.path.join(out, "opensearch_dashboards.yml"),
          fill(tmpl("opensearch_dashboards.yml.tmpl"), {"WAZUH_OIDC_SECRET": oidc}), 0o640, (UID, GID))
    write(os.path.join(out, "wazuh.yml"), fill(tmpl("wazuh.yml.tmpl"), {"API_PASSWORD": api}), 0o640, (UID, GID))

    # Environment files read by podman (root) when starting the containers.
    write(os.path.join(out, "manager.env"),
          f"INDEXER_PASSWORD={admin}\nAPI_PASSWORD={api}\n", 0o600)
    write(os.path.join(out, "dashboard.env"),
          f"INDEXER_PASSWORD={admin}\nDASHBOARD_PASSWORD={kibanaserver}\nAPI_PASSWORD={api}\n", 0o600)


if __name__ == "__main__":
    main(*sys.argv[1:4])
