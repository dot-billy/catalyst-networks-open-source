# Self-Hosting Security and Compatibility

## Nebula interface naming

Existing installations keep `tun.dev: nebula1` by default. Set
`NEBULA_INTERFACE_NAME_FROM_ORG_SLUG=True` to derive a deterministic interface
name from each organization slug. Generated names use only `[a-z0-9-]`, fit
within Linux's 15-byte interface-name limit, and use a hash suffix when a slug
must be truncated. Empty or invalid slugs still fall back to `nebula1`.

Enabling this setting changes the interface name for existing Linux and Windows
nodes after their next configuration sync. Update firewall, monitoring,
routing, and automation rules that refer to `nebula1` before enabling it.
macOS ignores this value and continues to allocate `utunN` automatically.

## Django admin TOTP

Admin TOTP is opt-in and disabled by default. Use this rollout order to avoid a
lockout:

1. Leave `ADMIN_REQUIRE_OTP=False` and deploy the `django-otp` migrations.
2. Enroll every staff user from the TOTP device section in Django admin, or run
   `python manage.py provision_totp user@example.com` and scan the printed
   `otpauth://` URL with an authenticator.
3. Confirm a second staff account can sign in with a password and TOTP code.
4. Set `ADMIN_REQUIRE_OTP=True` and restart the web processes.

The provisioning command prints the TOTP secret. Treat terminal scrollback,
container exec output, and CI logs containing that URL as sensitive.

For recovery, get a trusted shell in the running application and run:

```bash
python manage.py provision_totp user@example.com --reset
```

The reset is transactional: the previous device is replaced only inside one
database transaction. Keep `ADMIN_REQUIRE_OTP=False` until at least one tested
recovery path and a second enrolled administrator are available.

## Django admin IP allowlist

`ADMIN_IP_ALLOWLIST` is an optional comma-separated list of IPv4 or IPv6 CIDRs.
When set, clients outside those networks receive a 404 for `/admin/`; other
application routes are unaffected.

The default `ADMIN_TRUSTED_PROXY_HOPS=0` uses the direct peer address. If the
application is behind trusted proxies, set this to the exact number of trusted
proxies that append `X-Forwarded-For`. The middleware counts from the right and
ignores attacker-controlled prefixes. Test the setting from an allowed and a
denied address before relying on it for production access control.
