#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CUSTOMER_ONLY_PARTS = {
    'licensing',
    'plans',
    'support',
    'analytics',
    'saas_entitlements',
    'billing',
    'gitops',
}

SHARED_WATCH_PARTS = {
    'open_cvpn',
    'users',
    'organizations',
    'certificates',
    'nodes',
    'security_groups',
    'webhooks',
    'notifications',
    'sso',
    'templates',
    'static',
}

OSS_ONLY_PARTS = {
    'docs',
    'tools',
    'tests',
}


@dataclass(frozen=True)
class IntakeRow:
    status: str
    path: str
    area: str
    classification: str
    decision: str


def classify_path(path: str) -> tuple[str, str, str]:
    parts = set(Path(path).parts)
    first = Path(path).parts[0] if Path(path).parts else ''

    if parts & CUSTOMER_ONLY_PARTS:
        return first, 'port:customer-only', 'Reject by default unless a generic shared behavior is extracted.'
    if first in SHARED_WATCH_PARTS:
        return first, 'port:shared', 'Review for OSS parity port.'
    if first in OSS_ONLY_PARTS:
        return first, 'port:oss-only', 'Usually no customer port needed.'
    return first or 'unknown', 'port:needs-triage', 'Needs product-boundary review.'


def parse_name_status(output: str) -> list[IntakeRow]:
    rows: list[IntakeRow] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        columns = line.split('\t')
        status = columns[0]
        path = columns[-1]
        area, classification, decision = classify_path(path)
        rows.append(IntakeRow(status=status, path=path, area=area, classification=classification, decision=decision))
    return rows


def changed_files(customer_repo: Path, base: str, head: str) -> list[IntakeRow]:
    proc = subprocess.run(
        ['git', 'diff', '--name-status', f'{base}...{head}'],
        cwd=customer_repo,
        check=True,
        text=True,
        capture_output=True,
    )
    return parse_name_status(proc.stdout)


def render_markdown(rows: list[IntakeRow], source: str) -> str:
    lines = [
        f'# Port Intake: `{source}`',
        '',
        '| Status | Source File | Area | Class | Suggested Decision |',
        '| --- | --- | --- | --- | --- |',
    ]
    for row in rows:
        lines.append(
            f'| `{row.status}` | `{row.path}` | {row.area} | `{row.classification}` | {row.decision} |'
        )
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description='Classify customer_app changes for OSS port triage.')
    parser.add_argument('--customer-repo', default='../catalyst-networks-mono-repo/customer_app')
    parser.add_argument('--base', default='origin/main')
    parser.add_argument('--head', required=True)
    parser.add_argument('--format', choices=['markdown', 'json'], default='markdown')
    args = parser.parse_args()

    customer_repo = (ROOT / args.customer_repo).resolve()
    rows = changed_files(customer_repo, args.base, args.head)
    if args.format == 'json':
        print(json.dumps([row.__dict__ for row in rows], indent=2))
    else:
        print(render_markdown(rows, f'{args.base}...{args.head}'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
