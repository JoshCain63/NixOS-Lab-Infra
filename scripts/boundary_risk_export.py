#!/usr/bin/env python3
"""Export the risk factor of every Boundary target as JSON.

Boundary targets have no custom metadata fields, so the lab stores each
target's risk in its description, in this format (set by terraform/boundary):

    <role> | risk=<1-5> | tier=<tier> | data=<classification> | owners=<dept,...>

This script logs in to Boundary's API as a read-only account, reads every
target it can see, resolves each target's host address, and writes:

    {
      "generated_at": "...",
      "boundary_addr": "...",
      "risk_scale": {"min": 1, "max": 5},
      "targets": [
        {"name": "lt05", "risk": 5, "tier": "critical", "owners": ["Finance"], ...},
        ...
      ]
    }

Targets are sorted highest risk first. A target whose description doesn't
carry a valid risk is still listed, with "risk": null and an "error" field.

Standard library only. Defaults come from BOUNDARY_ADDR / BOUNDARY_CACERT,
and the password from --password-file or $CREDENTIALS_DIRECTORY/password
(systemd LoadCredential).
"""

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone

from boundary_api import RISK_MAX, RISK_MIN, Boundary, BoundaryError, read_password, target_metadata


def host_addresses(client, target):
    """Resolve the addresses of the hosts behind a target's host sets."""
    addresses = []
    for source in target.get("host_sources") or []:
        host_set = client.get(f"/v1/host-sets/{source['id']}")
        for host_id in host_set.get("host_ids") or []:
            address = (client.get(f"/v1/hosts/{host_id}").get("attributes") or {}).get("address")
            if address:
                addresses.append(address)
    # A target can also point straight at an address instead of host sets.
    if not addresses and target.get("address"):
        addresses.append(target["address"])
    return addresses


def export(client, scope_id="global"):
    records = []
    for summary in client.list_all("/v1/targets", {"scope_id": scope_id, "recursive": "true"}):
        target = client.get(f"/v1/targets/{summary['id']}")
        meta = target_metadata(target)
        record = {
            "id": target["id"],
            "name": target.get("name"),
            "scope": (target.get("scope") or {}).get("name"),
            "type": target.get("type"),
            "addresses": host_addresses(client, target),
            "port": (target.get("attributes") or {}).get("default_port"),
            "risk": meta["risk"],
            "tier": meta["tier"],
            "role": meta["role"],
            "data_classification": meta["data_classification"],
            "owners": meta["owners"],
        }
        if "error" in meta:
            record["error"] = meta["error"]
        records.append(record)

    # Highest risk first; unknown risk last; then by name.
    records.sort(key=lambda r: (-(r["risk"] or 0), r["name"] or ""))
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "boundary_addr": client.addr,
        "risk_scale": {"min": RISK_MIN, "max": RISK_MAX},
        "targets": records,
    }


def write_output(doc, path):
    text = json.dumps(doc, indent=2) + "\n"
    if path == "-":
        sys.stdout.write(text)
        return
    # Write atomically so readers never see a half-written file.
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".risk-export-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--addr", default=os.environ.get("BOUNDARY_ADDR", "http://127.0.0.1:9200"),
                   help="Boundary API address (default: $BOUNDARY_ADDR)")
    p.add_argument("--ca", default=os.environ.get("BOUNDARY_CACERT"),
                   help="CA bundle for https (default: $BOUNDARY_CACERT)")
    p.add_argument("--login", default="risk-exporter", help="login name (default: risk-exporter)")
    p.add_argument("--password-file", help="file holding the password")
    p.add_argument("--auth-method-id", help="password auth method (default: found by type)")
    p.add_argument("--scope-id", default="global", help="scope to list recursively (default: global)")
    p.add_argument("-o", "--output", default="-", help="output file, or - for stdout (default)")
    args = p.parse_args(argv)

    try:
        client = Boundary(args.addr, cafile=args.ca)
        client.login(args.auth_method_id or client.auth_method("password"), args.login,
                     read_password(args.password_file))
        doc = export(client, args.scope_id)
        write_output(doc, args.output)
    except (BoundaryError, OSError) as e:
        print(f"boundary-risk-export: {e}", file=sys.stderr)
        return 1

    bad = [t["name"] for t in doc["targets"] if t["risk"] is None]
    if bad:
        print(f"boundary-risk-export: no valid risk for: {', '.join(bad)}", file=sys.stderr)
    if args.output != "-":
        print(f"Exported {len(doc['targets'])} targets to {args.output}", file=sys.stderr)
    return 2 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
