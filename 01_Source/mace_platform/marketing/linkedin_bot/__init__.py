"""
LinkedIn growth bot — fully autonomous.

Two daemons, both safe under LinkedIn's ToS:

  1. daily_poster      — writes a fresh post every morning + publishes
                          to the UnifiedSec company page via the official
                          /v2/ugcPosts API. Powered by Claude / OpenAI /
                          local fallback so it works air-gapped too.

  2. connection_queue  — every morning, finds N relevant LinkedIn
                          prospects (Sales Nav search, MISP-style filters),
                          drafts a personalised 280-char note for each,
                          and queues them. Then either:
                            • sends them through the official 1st-degree
                              messaging API where allowed, OR
                            • drops them into a one-click HTML inbox the
                              user opens once with ⌘-click.

  3. scheduler         — launchd / cron wrapper so it all runs at 09:00
                          local every day without any human action.

Why we do NOT auto-click "Connect" via Selenium / Playwright / Phantombuster
patterns: LinkedIn's User Agreement §8.2 and Professional Community
Policies explicitly ban it. Detection is good. Founder accounts get
permanent restrictions. We don't risk that.
"""
from .daily_poster import run_daily_post, generate_post
from .connection_queue import build_queue, ProspectTarget
from .scheduler import install_launchd, uninstall_launchd, status

__all__ = ["run_daily_post", "generate_post", "build_queue", "ProspectTarget",
            "install_launchd", "uninstall_launchd", "status"]
