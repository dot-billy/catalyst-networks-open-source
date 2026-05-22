#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BLOCKED_PATHS = re.compile(
    r"(^|/)(\.git|licensing|plans|support|analytics|certs_data|media|staticfiles|"
    r"\.superpowers|\.claude|\.cursor|\.codex|\.agents|venv|__pycache__)(/|$)|"
    r"(^|/)(\.env(?!\.example$|\.prod\.example$)(\..*)?|cookies\.txt|debug\.log|"
    r"build_deploy_logs\.json|celerybeat-schedule)$"
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
    r"LicenseMiddleware|license_context|LICENSE_FILE|(^|/)licensing/|"
    r"\b(pro|enterprise) license\b|\bpaid edition\b|\btrial\b|\bbilling\b|"
    r"\bsubscription\b|\bupgrade\b|customer administration|\bSLA\b|"
    r"\btelemetry\b|\banalytics\b)",
    re.IGNORECASE,
)

SAFE_PLACEHOLDER_VALUES = (
    "example",
    "change-me",
    "changeme",
    "placeholder",
    "your-",
    "test",
    "dummy",
    "local",
)

SAFE_EXACT_VALUES = {"", "postgres"}

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


def relative_name(path: Path) -> str | None:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return None


def expand_path(path: Path) -> tuple[list[Path], list[str]]:
    relative = relative_name(path)
    if relative is None:
        return [], [f"{path}: outside repository"]
    if BLOCKED_PATHS.search(relative):
        return [path], []
    if not path.exists():
        return [], [f"{relative}: path does not exist"]
    if not path.is_dir():
        return [path], []

    paths: list[Path] = []
    for child in path.iterdir():
        child_relative = relative_name(child)
        if child_relative is None:
            continue
        if child.is_dir() and BLOCKED_PATHS.search(child_relative):
            continue
        child_paths, child_findings = expand_path(child)
        paths.extend(child_paths)
        if child_findings:
            return paths, child_findings
    return paths, []


def is_safe_placeholder_secret(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return True
    if "=" not in stripped:
        return False
    _, value = stripped.split("=", 1)
    value = value.split("#", 1)[0].strip().strip("\"'")
    lowered = value.lower()
    compact = re.sub(r"[^A-Za-z0-9]", "", value)
    character_classes = sum(
        (
            any(char.islower() for char in compact),
            any(char.isupper() for char in compact),
            any(char.isdigit() for char in compact),
        )
    )
    if value.startswith("AKIA") or (len(compact) >= 32 and character_classes >= 3):
        return False
    return lowered in SAFE_EXACT_VALUES or any(token in lowered for token in SAFE_PLACEHOLDER_VALUES)


def scan_file(path: Path) -> list[str]:
    relative = relative_name(path)
    if relative is None:
        return [f"{path}: outside repository"]
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
        if SECRET_PATTERNS.search(line) and not is_safe_placeholder_secret(line):
            findings.append(f"{relative}:{lineno}: secret-like value")
        if BUSINESS_PATTERNS.search(line):
            findings.append(f"{relative}:{lineno}: business/private term")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="Optional paths to scan. Defaults to changed files.")
    args = parser.parse_args()
    paths = [Path(p).resolve() for p in args.paths] if args.paths else changed_files()
    findings: list[str] = []
    for path in paths:
        expanded_paths, path_findings = expand_path(path.resolve())
        findings.extend(path_findings)
        for expanded_path in expanded_paths:
            findings.extend(scan_file(expanded_path.resolve()))
    if findings:
        print("OSS guard scan failed:")
        for finding in findings:
            print(f"  - {finding}")
        return 1
    print("OSS guard scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
