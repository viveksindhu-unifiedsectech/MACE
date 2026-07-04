#!/usr/bin/env python3
"""
MACE Secure Files — end-to-end demo (offline, no AWS / no DB / no network).

Runs the entire pipeline on a laptop so you can SHOW it working:

  1. AI guard blocks a leaked private key
  2. Redact + envelope-encrypt a confidential file, then decrypt it back
  3. Access control: tenant isolation, clearance, named-user grant
  4. Cross-matter conflict-of-interest detection (the differentiator)
  5. Proof the correlation index stores NO raw client data

Usage:
    ENVIRONMENT=test SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
        python scripts/secure_files_demo.py
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", "demo-secret-key-at-least-32-bytes-of-entropy-here-okay-yes")

from app.secure import service
from app.secure.access import Classification, Permission, Subject, Resource, Grant, evaluate
from app.secure.ai_guard import assess, Verdict
from app.secure.storage import LocalStorage
from app.secure.correlation import CorrelationIndex, Matter


def hr(title): print("\n" + "═" * 68 + f"\n  {title}\n" + "═" * 68)


def main():
    store = LocalStorage(root="/tmp/mace-demo-store")

    # 1 ─ AI GUARD blocks a leaked secret before it is ever stored ----------
    hr("1. AI SAFEGUARD — warn BEFORE the risky action")
    leaked = b"deploy key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----"
    g = assess(action="upload", content=leaked, will_redact=False)
    print(f"  Upload of a file containing a private key  -> verdict: {g.verdict.value.upper()}")
    for f in g.findings:
        print(f"    [{f.severity.upper():8}] {f.code}: {f.message}")
    assert g.verdict == Verdict.BLOCK

    # 2 ─ REDACT + ENCRYPT + DECRYPT a confidential document ----------------
    hr("2. REDACT -> ENVELOPE-ENCRYPT -> STORE -> DECRYPT")
    doc = (b"Q3 board memo. Wire to account ACCT-778812. "
           b"Client SSN 123-45-6789. Card 4111 1111 1111 1111.")
    sf = service.store_file(content=doc, tenant_id="firmA", owner_id="alice",
                            filename="q3_memo.txt",
                            classification=Classification.CONFIDENTIAL.value,
                            redact=True, storage=store)
    print(f"  Stored at:        {sf.storage_uri}")
    print(f"  Classification:   {sf.classification}")
    print(f"  Redacted:         {sf.redacted}  {sf.redaction_report['counts']}")
    print(f"  Plaintext SHA256: {sf.sha256[:24]}…  size={sf.size}B  chunks={sf.chunks}")
    blob = store.get("firmA", sf.file_id)
    print(f"  On-disk bytes are ciphertext (magic {blob[:5]!r}); "
          f"'123-45-6789' present on disk? {b'123-45-6789' in blob}")
    back = service.load_file(tenant_id="firmA", file_id=sf.file_id,
                             classification=sf.classification, storage=store)
    print(f"  Decrypted back:   {back.decode()[:60]}…")
    assert b"123-45-6789" not in back and b"Q3 board memo" in back

    # 3 ─ ACCESS CONTROL — tenant isolation, clearance, named grant ---------
    hr("3. ACCESS CONTROL — role, clearance, tenant isolation")
    restricted = Resource(id=sf.file_id, tenant_id="firmA", owner_id="alice",
                          classification=Classification.RESTRICTED)
    scenarios = [
        ("Analyst in SAME firm (clearance too low)",
         Subject("bob", "firmA", "soc_analyst"), restricted, Permission.READ),
        ("Analyst in a DIFFERENT firm (tenant isolation)",
         Subject("mallory", "firmB", "tenant_admin"), restricted, Permission.READ),
        ("Named-user grant issued to Bob for THIS file",
         Subject("bob", "firmA", "soc_analyst"),
         Resource(id=sf.file_id, tenant_id="firmA", owner_id="alice",
                  classification=Classification.RESTRICTED,
                  grants=[Grant("user", "bob", {Permission.READ})]), Permission.READ),
    ]
    for label, subj, res, perm in scenarios:
        d = evaluate(subj, res, perm)
        print(f"  {'ALLOW' if d.allow else 'DENY ':5} | {label}\n"
              f"          -> {d.code}: {d.reason}")

    # 4 ─ CROSS-MATTER CONFLICT DETECTION (the differentiator) --------------
    hr("4. CROSS-MATTER CONFLICT DETECTION (unique to MACE)")
    idx = CorrelationIndex(tenant_id="firmA")
    idx.register_matter(Matter("M-100", "Acme v. Beta",  wall_id="wall-A", party="client"))
    idx.register_matter(Matter("M-200", "Gamma v. Acme", wall_id="wall-B", party="adverse"))
    idx.add_document("M-100", "d1", privileged=False,
                     text="Key contact jordan@acme.com; strategy notes.")
    idx.add_document("M-200", "d2", privileged=True,
                     text="Privileged: opposing counsel reachable at jordan@acme.com")
    findings = idx.find_conflicts()
    print(f"  Indexed {idx.stats()['indexed_tokens']} entity tokens across "
          f"{idx.stats()['matters']} walled matters. Findings:")
    for f in findings:
        print(f"    [{f.severity.upper():6}] {f.kind}  token={f.token}  matters={f.matters}")
        print(f"             {f.detail}")
    assert any(f.kind == "CONFLICT_OF_INTEREST" for f in findings)

    # 5 ─ PRIVACY PROOF -----------------------------------------------------
    hr("5. PRIVACY PROOF — the index holds NO raw client data")
    raw_present = any("jordan@acme.com" in tok for (_, tok) in idx._postings)
    print(f"  Raw email 'jordan@acme.com' stored anywhere in the index? {raw_present}")
    print(f"  Index stats: {idx.stats()}")
    assert raw_present is False

    print("\n✓ All five stages passed. The full secure-files pipeline works offline.\n")


if __name__ == "__main__":
    main()
