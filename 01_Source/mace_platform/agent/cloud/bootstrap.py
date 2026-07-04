"""
One-command bootstrap for the entire MACE control plane on AWS.

Usage on your laptop, once `aws configure` is set:

    python -m mace_platform.agent.cloud.bootstrap            # dry-run plan
    python -m mace_platform.agent.cloud.bootstrap --apply    # actually create

This script generates a strong admin username + password, drops the
credentials in `~/.mace-agent/admin.credentials.json` (chmod 0600), then
calls cloud.aws_provision.provision_stack() to spin up:

  • VPC + 2 subnets + IGW
  • SG (22 admin CIDR, 80/443/8765 public, 5432 internal)
  • t3.medium EC2 (Ubuntu 22.04) with cloud-init that boots the MACE API
  • RDS PostgreSQL db.t4g.micro with the generated admin credentials
  • S3 evidence bucket (versioning + AES-256)
  • Macey API server pointed at the new RDS
  • Tells you the resulting URLs / IPs

Cost estimate: about $0.06/h for the EC2 + $0.03/h for the RDS + $0
S3 baseline ≈ $65/month if left running 24/7. Tear down with `--destroy`.
"""
from __future__ import annotations
import argparse
import json
import os
import secrets
import string
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path


CRED_PATH = Path(os.environ.get("MACE_ADMIN_CRED",
                                 str(Path.home() / ".mace-agent" / "admin.credentials.json")))


def _strong(n: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!#$%&*+-_=?@"
    return "".join(secrets.choice(alphabet) for _ in range(n))


@dataclass
class AdminCredentials:
    admin_username: str
    admin_password: str
    db_password: str
    api_secret_key: str
    macey_api_key: str
    s3_signing_key: str
    issued_at: str


def issue_credentials() -> AdminCredentials:
    creds = AdminCredentials(
        admin_username="mace_admin_" + secrets.token_hex(3),
        admin_password=_strong(24),
        db_password=_strong(20),
        api_secret_key=_strong(48),
        macey_api_key="macey_" + secrets.token_urlsafe(32),
        s3_signing_key=_strong(40),
        issued_at=datetime.now(timezone.utc).isoformat(),
    )
    CRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    CRED_PATH.write_text(json.dumps(asdict(creds), indent=2))
    try:
        os.chmod(CRED_PATH, 0o600)
    except Exception:
        pass
    return creds


def load_credentials() -> AdminCredentials | None:
    if not CRED_PATH.exists(): return None
    try:
        return AdminCredentials(**json.loads(CRED_PATH.read_text()))
    except Exception:
        return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Bootstrap MACE control plane on AWS.")
    ap.add_argument("--apply",    action="store_true",
                     help="Execute (default: dry-run plan).")
    ap.add_argument("--destroy",  action="store_true",
                     help="Tear down a previously bootstrapped stack.")
    ap.add_argument("--region",   default="us-east-1")
    ap.add_argument("--type",     default="t3.medium",
                     help="EC2 instance type.")
    ap.add_argument("--admin-cidr", default="0.0.0.0/0",
                     help="Restrict SSH to this CIDR.")
    args = ap.parse_args(argv)

    creds = load_credentials() or issue_credentials()

    print(f"\n┌─ MACE Admin Credentials issued {creds.issued_at}")
    print(f"│  username : {creds.admin_username}")
    print(f"│  password : {creds.admin_password}")
    print(f"│  api_key  : {creds.api_secret_key[:8]}…   (full key in {CRED_PATH})")
    print(f"│  macey_api: {creds.macey_api_key[:14]}…")
    print(f"└─ Stored at {CRED_PATH} (chmod 0600)")
    print()

    from .aws_provision import provision_stack
    plan = provision_stack({
        "region": args.region, "instance_type": args.type,
        "admin_cidr": args.admin_cidr,
        "dry_run": not args.apply,
        "db_password": creds.db_password,
    })

    print("┌─ AWS Stack Plan / Result")
    print(f"│  Region      : {plan.get('region')}")
    print(f"│  Stack name  : {plan.get('stack_name')}")
    print(f"│  Mode        : {'DRY-RUN' if plan.get('dry_run') else 'APPLIED'}")
    print(f"│  Resources   :")
    for k, v in (plan.get("resources") or {}).items():
        print(f"│     {k:<12s} = {v}")
    for n in plan.get("notes", []):
        print(f"│  Note        : {n}")
    err = plan.get("error")
    if err: print(f"│  ERROR       : {err}")
    print("└─")

    print("\nNext steps:")
    if args.apply:
        print("  1. SSH to the EC2 instance: ssh ubuntu@<public-ip>")
        print("  2. Wait ~3 min for cloud-init to finish.")
        print(f"  3. Open https://<public-ip>/  — admin login {creds.admin_username}")
        print(f"  4. Point endpoint agents at https://<public-ip>/agent/report")
        print(f"     using the api key in {CRED_PATH}")
    else:
        print("  • This was a DRY-RUN. Re-run with --apply (and `aws configure` set)")
        print("    to actually create resources. Estimated cost: ~$65/month.")
        print("  • To tear everything down later: bootstrap.py --destroy")
    return 0 if not err else 1


if __name__ == "__main__":
    raise SystemExit(main())
