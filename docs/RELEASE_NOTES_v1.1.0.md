# Catalyst Networks OSS v1.1.0

This release brings the public application up to date with the remaining
reusable customer-app fixes and adds stronger release safeguards.

## Highlights

- Fixes organization-scoped CA creation redirects.
- Redacts node authentication and permission decision logs.
- Prevents same-second certificate filename collisions and restores the node
  delete confirmation screen.
- Adds opt-in organization-derived Nebula interface names.
- Adds disabled-by-default Django admin TOTP enforcement and an optional CIDR
  allowlist.
- Documents Google Workspace and generic OIDC support, current Security Groups,
  and configuration overrides.
- Enforces Node 24 GitHub Actions and content-aware Gitleaks history scanning.

## Compatibility and migration notes

Run normal Django migrations before starting the updated web process; this
includes the `django-otp` tables. Admin OTP remains disabled until
`ADMIN_REQUIRE_OTP=True`.

The default Nebula interface remains `nebula1`. If
`NEBULA_INTERFACE_NAME_FROM_ORG_SLUG=True` is enabled, existing Linux and
Windows nodes change interface name after their next configuration sync. Update
interface-specific firewall, monitoring, and routing rules first. macOS
continues to auto-assign `utunN`.

See `docs/SELF_HOSTING_SECURITY.md` for enrollment, recovery, proxy, and rollout
guidance.
