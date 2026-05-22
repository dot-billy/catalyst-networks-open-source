#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BLOCKED_PATHS = re.compile(
    r"(^|/)(licensing|plans|support|analytics|certs_data|media|staticfiles|"
    r"\.superpowers|\.claude|\.cursor|\.codex|\.agents|venv|__pycache__)(/|$)|"
    r"(^|/)(\.env(\..*)?|cookies\.txt|debug\.log|build_deploy_logs\.json|celerybeat-schedule)$"
)

SECRET_PATTERNS = re.compile(
    r"(SECRET_KEY\s*=|JWT_SECRET_KEY\s*=|FIELD_ENCRYPTION_KEY\s*=|AWS_[A-Z0-9_]*\s*=|"
    r"POSTGRES_PASSWORD\s*=|REDIS_PASSWORD\s*=|MAILGUN_API_KEY\s*=|"
    r"SUPPORT_GATEWAY_SECRET\s*=|DATABASE_URL\s*=|BEGIN [A-Z ]*PRIVATE KEY|"
    r"[A-Z0-9_]*PRIVATE_KEY\s*=|Authorization:\s*Bearer|\bBearer\s+|x-api-key\s*[:=]|"
    r"sessionid\s*=|csrftoken\s*=|"
    r"NEBULA_(API_PASSWORD|REGISTRATION_TOKEN|REFRESH_TOKEN)\s*=|"
    r"[A-Z0-9_]*REGISTRATION[A-Z0-9_]*TOKEN\s*=)",
    re.IGNORECASE,
)

BUSINESS_PATTERNS = re.compile(
    r"(catalystnetworks\.io|catalystnetworks\.com|app\.catalystnetworks\.io|"
    r"demo\.catalystnetworks\.io|/etc/catalyst|customer-app-secrets|do-prod|"
    r"\blicens(e|ing)\b|\bedition\b|\benterprise\b|\bpro\b|\btrial\b|\bbilling\b|"
    r"\bsubscription\b|\bupgrade\b|\bdemo\b|customer administration|\bSLA\b|"
    r"\btelemetry\b|\banalytics\b)",
    re.IGNORECASE,
)

ALLOWLIST = {
    "docs/superpowers/specs/2026-05-22-oss-customer-app-migration-design.md",
    "docs/superpowers/plans/2026-05-22-oss-customer-app-migration.md",
    "tools/oss_guard_scan.py",
}


def changed_files() -> list[Path]:
    names: dict[str, None] = {}
    commands = (
        ["git", "diff", "--name-only", "--cached", "HEAD"],
        ["git", "diff", "--name-only"],
        ["git", "ls-files", "--others", "--exclude-standard"],
    )
    for command in commands:
        proc = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        for line in proc.stdout.splitlines():
            name = line.strip()
            if name:
                names[name] = None
    return [ROOT / name for name in names]


def scan_file(path: Path) -> list[str]:
    relative = path.relative_to(ROOT).as_posix()
    findings: list[str] = []
    if relative in ALLOWLIST:
        return findings
    if BLOCKED_PATHS.search(relative):
        findings.append(f"{relative}: blocked path")
        return findings
    if not path.is_file():
        return findings
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        findings.append(f"{relative}: non-text file needs manual review")
        return findings
    for lineno, line in enumerate(text.splitlines(), 1):
        if SECRET_PATTERNS.search(line):
            findings.append(f"{relative}:{lineno}: secret-like value")
        if BUSINESS_PATTERNS.search(line):
            findings.append(f"{relative}:{lineno}: business/private term")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="Optional paths to scan. Defaults to changed files.")
    args = parser.parse_args()
    paths = [ROOT / p for p in args.paths] if args.paths else changed_files()
    findings: list[str] = []
    for path in paths:
        findings.extend(scan_file(path.resolve()))
    if findings:
        print("OSS guard scan failed:")
        for finding in findings:
            print(f"  - {finding}")
        return 1
    print("OSS guard scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
