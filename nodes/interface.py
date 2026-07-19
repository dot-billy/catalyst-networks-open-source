"""Nebula interface naming helpers for self-hosted deployments."""

import hashlib
import re


FALLBACK = 'nebula1'
_ALLOWED = re.compile(r'[^a-z0-9-]')
_DASHES = re.compile(r'-+')


def _sanitize(org_slug):
    value = org_slug.lower()
    value = _ALLOWED.sub('', value)
    return _DASHES.sub('-', value).strip('-')


def nebula_interface_name(org_slug, prefix='cn-', max_len=15):
    """Return a deterministic Linux-safe interface name for an org slug."""
    if not org_slug:
        return FALLBACK

    sanitized = _sanitize(org_slug)
    if not sanitized:
        return FALLBACK

    candidate = prefix + sanitized
    if len(candidate.encode('utf-8')) <= max_len:
        return candidate

    digest = hashlib.sha256(org_slug.encode('utf-8')).hexdigest()[:4]
    head_budget = max_len - len(prefix) - 1 - len(digest)
    head = sanitized[:head_budget].rstrip('-')
    if not head:
        return FALLBACK
    return f'{prefix}{head}-{digest}'
