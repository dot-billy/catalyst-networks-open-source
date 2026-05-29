#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
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
    r"POSTGRES_PASSWORD\s*=|REDIS_PASSWORD\s*=|MAILGUN_API_KEY\s*=|RESEND_API_KEY\s*[:=]|"
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
    r"\b(pro|enterprise) license\b|\blicense gate\b|\benterprise plan limits\b|"
    r"\bdemo mode flows\b|\bpaid edition\b|\btrial\b|\bbilling\b|\bsubscription\b|"
    r"\bupgrade\b|customer administration|\bSLA\b|\btelemetry\b|\banalytics\b)",
    re.IGNORECASE,
)

SAFE_PLACEHOLDER_VALUES = (
    "change-me",
    "changeme",
    "placeholder",
)

SAFE_EXACT_VALUES = {"", "postgres", "localhost", "local", "test", "dummy", "example"}

SAFE_PLUMBING_PATTERNS = re.compile(
    r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*("
    r"_[A-Za-z0-9_]*|os\.(getenv|environ\.get)\([\"'][A-Z0-9_]+[\"']\)"
    r")\s*(#.*)?$"
)

ENV_ASSIGNMENT_PATTERN = re.compile(r"\b[A-Z0-9_]+\s*=\s*([^\s`,;]+)")

ALLOWLIST = {
    "docs/superpowers/specs/2026-05-22-oss-customer-app-migration-design.md",
    "docs/superpowers/plans/2026-05-22-oss-customer-app-migration.md",
    "tools/oss_guard_scan.py",
}

EXPECTED_BINARY_HASHES = {
    "static/fonts/inter/Inter-Bold.woff2": "98c66e49c299c5675426bf5562b1876c2b6b9bd8dc90a8922a49703ed4848813",
    "static/fonts/inter/Inter-Light.woff2": "6ee2d73d12b1510a6927dbe48ded74323a562197b60bc391ccf918d17e4d0074",
    "static/fonts/inter/Inter-Medium.woff2": "7e80d9f65861ee6836a0081d4e75d88fb8789e5651d05edbc49640442a9610ee",
    "static/fonts/inter/Inter-Regular.woff2": "338239f6b590b8ced3bf857654d32da3fd3663294cd3003651ed57aa3abd7aa1",
    "static/fonts/inter/Inter-SemiBold.woff2": "5013f48d77ab627b1db7c2415914284ef09abc3f60a8e0d0d8f3cd1bfebefb5e",
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
            if name and (ROOT / name).exists():
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


def is_safe_placeholder_value(value: str) -> bool:
    value = value.strip().strip("\"'")
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
    placeholderish = lowered.startswith("your-") or any(
        token in lowered for token in SAFE_PLACEHOLDER_VALUES
    )
    return lowered in SAFE_EXACT_VALUES or placeholderish


def is_known_safe_secret_like_line(relative: str, stripped: str) -> bool:
    return (
        relative == "nodes/api_registration.py"
        and stripped == "registration_token = serializers.CharField(max_length=255)"
    )


def is_safe_placeholder_secret(line: str, relative: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return True
    if is_known_safe_secret_like_line(relative, stripped):
        return True
    if SAFE_PLUMBING_PATTERNS.search(stripped):
        return True
    if "=" not in stripped:
        return False
    if not re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
        values = ENV_ASSIGNMENT_PATTERN.findall(stripped)
        return bool(values) and all(is_safe_placeholder_value(value) for value in values)
    _, value = stripped.split("=", 1)
    value = value.split("#", 1)[0].strip().strip("\"'")
    return is_safe_placeholder_value(value)


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
        expected_hash = EXPECTED_BINARY_HASHES.get(relative)
        if expected_hash:
            actual_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                findings.append(f"{relative}: binary asset hash mismatch")
            return findings
        findings.append(f"{relative}: non-text file needs manual review")
        return findings
    for lineno, line in enumerate(text.splitlines(), 1):
        if SECRET_PATTERNS.search(line) and not is_safe_placeholder_secret(line, relative):
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
