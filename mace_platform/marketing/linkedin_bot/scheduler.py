"""
Daily scheduler. Installs a per-user launchd job (macOS) or cron
(Linux/WSL) that runs the LinkedIn bot every day at 09:00 local without
any human interaction.

Two jobs:
  • io.unifiedsec.lkpost  — fires daily_poster.run_daily_post() at 09:00
  • io.unifiedsec.lkqueue — fires connection_queue.build_queue() at 09:05

CLI:
  python -m mace_platform.marketing.linkedin_bot.scheduler install
  python -m mace_platform.marketing.linkedin_bot.scheduler uninstall
  python -m mace_platform.marketing.linkedin_bot.scheduler status
  python -m mace_platform.marketing.linkedin_bot.scheduler run-now   # fire both immediately
"""
from __future__ import annotations
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Tuple

LAUNCHD_DIR = Path.home() / "Library" / "LaunchAgents"
POST_LABEL  = "io.unifiedsec.lkpost"
QUEUE_LABEL = "io.unifiedsec.lkqueue"
LOG_DIR     = Path.home() / ".mace-agent" / "marketing" / "logs"


def _plist(label: str, args: list, hour: int, minute: int,
            workdir: str, py: str) -> str:
    env_keys = ("ANTHROPIC_API_KEY","ANTHROPIC_MODEL","OPENAI_API_KEY","OPENAI_MODEL","PATH","HOME")
    env_dict = ""
    for k in env_keys:
        v = os.environ.get(k, "")
        if v:
            env_dict += f"      <key>{k}</key><string>{_xml_escape(v)}</string>\n"
    args_xml = "\n".join(f"    <string>{_xml_escape(a)}</string>" for a in [py, "-m"] + args)
    log_out = LOG_DIR / f"{label}.out.log"
    log_err = LOG_DIR / f"{label}.err.log"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args_xml}
  </array>
  <key>WorkingDirectory</key><string>{_xml_escape(workdir)}</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>{hour}</integer>
    <key>Minute</key><integer>{minute}</integer>
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
{env_dict}  </dict>
  <key>StandardOutPath</key><string>{_xml_escape(str(log_out))}</string>
  <key>StandardErrorPath</key><string>{_xml_escape(str(log_err))}</string>
  <key>RunAtLoad</key><false/>
</dict>
</plist>
"""


def _xml_escape(s: str) -> str:
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
             .replace('"',"&quot;").replace("'","&apos;"))


def _project_root() -> Path:
    # mace_platform/marketing/linkedin_bot/scheduler.py → up 3
    return Path(__file__).resolve().parents[3]


def install_launchd(post_hour: int = 9, post_minute: int = 0,
                     queue_hour: int = 9, queue_minute: int = 5) -> Tuple[Path, Path]:
    if platform.system() != "Darwin":
        raise RuntimeError("install_launchd only supported on macOS. Use cron on Linux.")
    LAUNCHD_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    workdir = str(_project_root())
    py = sys.executable
    post_plist  = LAUNCHD_DIR / f"{POST_LABEL}.plist"
    queue_plist = LAUNCHD_DIR / f"{QUEUE_LABEL}.plist"
    post_plist.write_text(_plist(POST_LABEL,
        ["mace_platform.marketing.linkedin_bot.daily_poster"],
        post_hour, post_minute, workdir, py))
    queue_plist.write_text(_plist(QUEUE_LABEL,
        ["mace_platform.marketing.linkedin_bot.connection_queue", "-n", "20"],
        queue_hour, queue_minute, workdir, py))
    # Reload
    for p in (post_plist, queue_plist):
        subprocess.run(["launchctl","unload",str(p)], capture_output=True)
        subprocess.run(["launchctl","load",str(p)], check=False)
    return post_plist, queue_plist


def uninstall_launchd() -> None:
    for label in (POST_LABEL, QUEUE_LABEL):
        p = LAUNCHD_DIR / f"{label}.plist"
        if p.exists():
            subprocess.run(["launchctl","unload",str(p)], capture_output=True)
            p.unlink()


def status() -> dict:
    out: dict = {}
    if platform.system() != "Darwin":
        return {"system": platform.system(), "installed": False,
                "note": "Use cron on Linux."}
    for label in (POST_LABEL, QUEUE_LABEL):
        p = LAUNCHD_DIR / f"{label}.plist"
        listed = subprocess.run(["launchctl","list"], capture_output=True,
                                 text=True).stdout
        out[label] = {
            "plist_path": str(p),
            "plist_exists": p.exists(),
            "loaded": label in listed,
        }
    return out


def run_now() -> None:
    """Fire both jobs immediately (for testing)."""
    from .daily_poster import run_daily_post
    from .connection_queue import build_queue
    print("▶ Running daily_post …")
    rec = run_daily_post(dry_run=False)
    print(f"  posted={rec.success}  theme={rec.theme_id}  provider={rec.provider}")
    print("▶ Running connection_queue …")
    q = build_queue(n=20, dry_run=False)
    print(f"  queued {len(q)} prospects → ~/.mace-agent/marketing/queue.html")


def main(argv=None):
    cmd = (argv or sys.argv[1:])[:1]
    cmd = cmd[0] if cmd else "status"
    if cmd == "install":
        post, queue = install_launchd()
        print(f"  ✓ Installed:\n    {post}\n    {queue}")
        print("  Bot will fire daily at 09:00 (post) and 09:05 (queue) local time.")
    elif cmd == "uninstall":
        uninstall_launchd()
        print("  ✓ Uninstalled.")
    elif cmd == "status":
        import json as _j
        print(_j.dumps(status(), indent=2))
    elif cmd == "run-now":
        run_now()
    else:
        print(f"Unknown command: {cmd}. Use install | uninstall | status | run-now")


if __name__ == "__main__":
    main()
