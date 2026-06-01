# SSO Settings and OIDC Discoverability Design

## Context

OSS Catalyst already has organization-scoped SAML SSO support: `/sso/<slug>/configure/`, `SSOConfigurationForm`, SAML login/ACS/metadata routes, password-login enforcement, and an existing configuration template. The original missing admin UI piece was discoverability. The scope now also includes adding OIDC-based sign-in, with Google as the first polished provider path.

This design applies the selected visual direction, Option B: persistent access. SSO remains a normal open-source organization settings surface, but the settings surface should support both existing SAML configuration and new OIDC/Google configuration.

The selected Django foundation for OIDC and Google sign-in is `django-allauth`. Allauth should own the OAuth/OIDC protocol mechanics, while the Catalyst SSO layer owns organization scoping, provider selection, membership rules, provisioning, and SSO enforcement.

## Goals

- Make SSO settings easy for organization owners and admins to find from any organization-scoped page.
- Keep a single canonical SSO settings surface for both SAML and OIDC providers.
- Add OIDC as a second organization SSO provider type alongside the existing SAML implementation.
- Provide a Google Workspace preset built on `django-allauth` Google provider support, alongside generic OIDC provider support.
- Preserve current SAML behavior while introducing OIDC.
- Preserve current permission behavior: owners/admins can configure SSO; non-admin members should not see the SSO navigation item.
- Keep the UI consistent with the current two-rail Catalyst workspace shell, mobile menu, and organization command center.
- Avoid plan, license, hosted-service, or enterprise-gating language. SSO is an open-source organization feature.

## Non-Goals

- No custom hand-rolled OAuth/OIDC authorization-code implementation.
- No read-only SSO status page for regular members.
- No duplicate SSO form embedded in the organization summary page.
- No replacement of the existing SAML login, ACS, or metadata routes.
- No broad social-login marketplace beyond Google plus generic OIDC.

## Approved Visual Approach

Add **SSO** as a persistent organization navigation item, visible only when `organization.role` is `owner` or `admin`.

Placement:

- Desktop organization sidebar: add an `SSO` item near access-management destinations, immediately after `Members` and before `Webhooks`.
- Mobile organization menu: mirror the same `SSO` item and visibility rule.
- Organization summary `Resource Shortcuts`: add an admin-only SSO shortcut so owners/admins have a second visible path from the command center.
- Header action: the existing `SSO Settings` action can remain, but the persistent nav item becomes the primary discovery path.

Active state:

- The SSO nav item should be active when the request path is within `/sso/`.
- It should link to `{% url 'sso:configure' organization.slug %}`.

## Page Behavior

The existing SSO configure page remains the canonical settings UI, but should become provider-aware. It should support:

- Provider type selection: `SAML` or `OIDC`.
- OIDC provider mode: `Google Workspace` preset or `Generic OIDC`.
- Shared controls: enabled/disabled status, auto-create users, default role, enforce SSO.

For SAML, the page should continue to show:

- SSO enabled/disabled status and enable/disable action.
- Service Provider details: Entity ID/Audience URI, ACS URL, metadata XML URL.
- Identity Provider fields: entity ID, SSO URL, optional SLO URL, X.509 certificate.
- Attribute mapping fields.
- SSO login URL when SSO is enabled.

For OIDC/Google, the page should show:

- Provider display name.
- Client ID and client secret.
- Google Workspace hosted-domain control for the Google preset.
- Issuer or discovery URL for generic OIDC.
- Scope defaults of `openid email profile`.
- Claim mapping for email, first name, and last name, with sensible defaults.
- Callback/redirect URL values to copy into the provider console.

The page should continue to require organization owner/admin membership. A direct URL visit by a non-admin member should remain blocked by the existing view permission check.

## Auth Architecture

Use `django-allauth` for OIDC and Google protocol handling:

- Add the core allauth apps needed for account and social login.
- Add the Google provider.
- Add the OpenID Connect provider for generic OIDC support.
- Configure allauth to require/consume email identities and avoid username-first behavior.
- Route successful allauth authentication through Catalyst-specific checks before final login is considered complete.

Catalyst-specific behavior should remain outside allauth:

- Resolve which organization/provider initiated the login.
- Validate the returned identity against the organization SSO configuration.
- Enforce allowed hosted domain or issuer/provider constraints.
- Create or update the Django user only after provider validation succeeds.
- Create membership using the SSO default role when auto-provisioning is enabled.
- Reject non-members when auto-provisioning is disabled.
- Preserve existing password-login blocking behavior for organizations enforcing SSO.

Client secrets must not be logged. They should be stored using an encrypted-secret pattern consistent with the project; if no suitable reusable encrypted field exists for SSO, add one as part of implementation.

## Implementation Notes

Templates to update:

- `templates/base/base.html`: desktop organization sidebar item.
- `templates/components/mobile_nav.html`: mobile organization menu item.
- `templates/organizations/detail.html`: `Resource Shortcuts` SSO card for owners/admins.
- `sso/templates/sso/configure.html`: provider-aware settings UI for SAML, Google Workspace, and generic OIDC.

Likely Python areas:

- `requirements.txt`: add `django-allauth`.
- `open_cvpn/settings.py`: add allauth apps, authentication backend, provider settings, and any required site/account settings.
- `open_cvpn/urls.py`: include allauth routes or thin Catalyst wrapper routes.
- `sso/models.py`: extend or add provider configuration models for OIDC/Google without breaking existing SAML data.
- `sso/forms.py`: add provider-aware forms.
- `sso/views.py`: add OIDC/Google initiation and callback integration points around allauth.
- `sso/policies.py`: keep SSO enforcement protocol-neutral.

The desktop and mobile nav checks should use the existing role convention already present in the templates:

```django
{% if organization.role == 'owner' or organization.role == 'admin' %}
```

## Testing

Add or update tests to cover:

- Owners/admins see the SSO navigation entry on organization-scoped pages.
- Regular members do not see the SSO navigation entry.
- Owners/admins see the SSO shortcut on the organization summary page.
- Regular members do not see the SSO shortcut.
- The SSO configure page still blocks non-admin direct access.
- The SSO navigation active state is applied on `/sso/<slug>/configure/`.
- Existing SAML configuration and login tests continue to pass.
- Google/OIDC login accepts an allowed identity and creates membership when auto-provisioning is enabled.
- Google/OIDC login rejects disallowed hosted domains or issuer mismatches.
- Google/OIDC login rejects non-members when auto-provisioning is disabled.
- Enforce-SSO blocks password login regardless of whether the org uses SAML or OIDC.

## Acceptance Criteria

- From any organization-scoped desktop page, an owner/admin can reach SSO settings from the organization sidebar.
- From mobile navigation, an owner/admin can reach SSO settings from the current organization menu.
- Regular members do not see the SSO navigation or resource shortcut.
- SSO configuration remains centralized in the existing SSO configure view.
- Organization admins can configure existing SAML SSO.
- Organization admins can configure Google Workspace sign-in using allauth-backed Google provider handling.
- Organization admins can configure a generic OIDC provider using allauth-backed OIDC handling.
- SAML behavior is not regressed.
- There is no plan, license, hosted-service, or enterprise-gating language around SSO.
- The behavior is consistent with the matching `customer_app` design, aside from customer-app-only surrounding UI such as licensing or support links.
