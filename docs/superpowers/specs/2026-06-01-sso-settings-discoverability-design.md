# SSO Settings Discoverability Design

## Context

OSS Catalyst already has organization-scoped SAML SSO support: `/sso/<slug>/configure/`, `SSOConfigurationForm`, SAML login/ACS/metadata routes, password-login enforcement, and an existing configuration template. The missing admin UI piece is discoverability. Today, SSO is reachable from the organization detail header, but it is easy to miss among operational actions and it is not present in the persistent organization navigation.

This design applies the selected visual direction, Option B: persistent access. SSO remains a normal open-source organization settings surface rather than a new dashboard or duplicated form.

## Goals

- Make SSO settings easy for organization owners and admins to find from any organization-scoped page.
- Keep the existing SSO configuration page as the single canonical edit surface.
- Preserve current permission behavior: owners/admins can configure SSO; non-admin members should not see the SSO navigation item.
- Keep the UI consistent with the current two-rail Catalyst workspace shell, mobile menu, and organization command center.
- Avoid plan, license, hosted-service, or enterprise-gating language. SAML SSO is an open-source organization feature.

## Non-Goals

- No new SSO provider type beyond the existing SAML implementation.
- No read-only SSO status page for regular members.
- No duplicate SSO form embedded in the organization summary page.
- No changes to SAML authentication, ACS, metadata, or login enforcement behavior.

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

The existing SSO configure page remains the canonical settings UI. It should continue to show:

- SSO enabled/disabled status and enable/disable action.
- Service Provider details: Entity ID/Audience URI, ACS URL, metadata XML URL.
- Identity Provider fields: entity ID, SSO URL, optional SLO URL, X.509 certificate.
- Attribute mapping fields.
- Provisioning and access fields: auto-create users, default role, enforce SSO.
- SSO login URL when SSO is enabled.

The page should continue to require organization owner/admin membership. A direct URL visit by a non-admin member should remain blocked by the existing view permission check.

## Implementation Notes

Templates to update:

- `templates/base/base.html`: desktop organization sidebar item.
- `templates/components/mobile_nav.html`: mobile organization menu item.
- `templates/organizations/detail.html`: `Resource Shortcuts` SSO card for owners/admins.
- Existing `sso/templates/sso/configure.html` should only need visual touch-up if active-state or spacing problems are discovered during implementation.

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

## Acceptance Criteria

- From any organization-scoped desktop page, an owner/admin can reach SSO settings from the organization sidebar.
- From mobile navigation, an owner/admin can reach SSO settings from the current organization menu.
- Regular members do not see the SSO navigation or resource shortcut.
- SSO configuration remains centralized in the existing SSO configure view.
- There is no plan, license, hosted-service, or enterprise-gating language around SSO.
- The behavior is consistent with the matching `customer_app` design, aside from customer-app-only surrounding UI such as licensing or support links.
