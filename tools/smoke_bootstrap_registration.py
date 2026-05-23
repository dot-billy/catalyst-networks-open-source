#!/usr/bin/env python3
"""Smoke test first-user bootstrap registration against a running deployment."""

from __future__ import annotations

import argparse
import html.parser
import http.cookiejar
import os
import secrets
import sys
import time
import urllib.parse
import urllib.request


class SmokeResult:
    def __init__(self, email: str, final_url: str) -> None:
        self.email = email
        self.final_url = final_url


class SmokeFailure(RuntimeError):
    pass


class CsrfParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        values = dict(attrs)
        if values.get("name") == "csrfmiddlewaretoken":
            self.token = values.get("value")


def _default_opener_factory():
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))


def _url(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _read_response(response) -> str:
    return response.read().decode("utf-8", errors="replace")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise SmokeFailure(message)


def _get(opener, url: str, timeout: float):
    request = urllib.request.Request(url, method="GET")
    return opener.open(request, timeout=timeout)


def _post_form(opener, url: str, data: dict[str, str], referer: str, timeout: float):
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=encoded,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": referer,
        },
    )
    return opener.open(request, timeout=timeout)


def _csrf_token(body: str) -> str:
    parser = CsrfParser()
    parser.feed(body)
    _require(bool(parser.token), "register form did not include csrfmiddlewaretoken")
    return parser.token


def _generated_email() -> str:
    stamp = int(time.time())
    token = secrets.token_hex(4)
    return f"smoke-bootstrap-{stamp}-{token}@example.test"


def _generated_password() -> str:
    return f"{secrets.token_urlsafe(24)}A1!"


def run_smoke(
    base_url: str,
    email: str | None = None,
    password: str | None = None,
    opener_factory=_default_opener_factory,
    output=sys.stdout,
    timeout: float = 15,
) -> SmokeResult:
    """Run bootstrap registration smoke checks and return the account metadata."""

    email = email or _generated_email()
    password = password or _generated_password()
    base_url = base_url.rstrip("/")

    opener = opener_factory()

    health_url = _url(base_url, "/health/")
    response = _get(opener, health_url, timeout)
    body = _read_response(response).strip()
    _require(response.status == 200, f"health returned {response.status}")
    _require(body == '{"status": "ok"}', f"health body mismatch: {body!r}")
    print("health: 200 ok", file=output)

    login_url = _url(base_url, "/login/")
    response = _get(opener, login_url, timeout)
    body = _read_response(response)
    _require(response.status == 200, f"login before bootstrap returned {response.status}")
    _require("Create one" in body, "login before bootstrap did not include Create one")
    print("login before bootstrap: 200 signup available", file=output)

    register_url = _url(base_url, "/register/")
    response = _get(opener, register_url, timeout)
    body = _read_response(response)
    _require(response.status == 200, f"register before bootstrap returned {response.status}")
    _require("Bootstrap administrator" in body, "register page did not show bootstrap mode")
    _require("Create the first account" in body, "register page did not show first-account copy")
    csrf_token = _csrf_token(body)
    print("register before bootstrap: 200 bootstrap form", file=output)

    response = _post_form(
        opener,
        register_url,
        {
            "csrfmiddlewaretoken": csrf_token,
            "email": email,
            "password1": password,
            "password2": password,
        },
        referer=register_url,
        timeout=timeout,
    )
    body = _read_response(response)
    final_url = response.geturl()
    parsed_final = urllib.parse.urlparse(final_url)
    _require(response.status == 200, f"bootstrap POST final response returned {response.status}")
    _require(parsed_final.path == "/dashboard/", f"bootstrap POST ended at {final_url!r}")
    print(f"bootstrap account: {email}", file=output)
    print(f"bootstrap post: 200 redirected to {final_url}", file=output)

    fresh_opener = opener_factory()
    response = _get(fresh_opener, register_url, timeout)
    body = _read_response(response)
    _require(response.status == 200, f"register after bootstrap returned {response.status}")
    _require("Registration is closed" in body, "register after bootstrap did not close")
    _require('name="email"' not in body, "register after bootstrap still exposed email account field")
    print("register after bootstrap: 200 closed", file=output)

    response = _get(fresh_opener, login_url, timeout)
    body = _read_response(response)
    _require(response.status == 200, f"login after bootstrap returned {response.status}")
    _require("Create one" not in body, "login after bootstrap still showed Create one")
    _require("Need access?" in body, "login after bootstrap did not show access guidance")
    print("login after bootstrap: 200 signup hidden", file=output)

    return SmokeResult(email=email, final_url=final_url)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Base URL for the running deployment")
    parser.add_argument("--email", help="Email address to create; generated if omitted")
    parser.add_argument(
        "--password-env",
        default="SMOKE_BOOTSTRAP_PASSWORD",
        help="Environment variable containing the bootstrap password",
    )
    parser.add_argument("--timeout", type=float, default=15, help="HTTP timeout in seconds")
    args = parser.parse_args(argv)

    password = os.environ.get(args.password_env) or _generated_password()

    try:
        run_smoke(
            args.base_url,
            email=args.email,
            password=password,
            timeout=args.timeout,
        )
    except (SmokeFailure, urllib.error.URLError, TimeoutError) as exc:
        print(f"smoke failed: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
