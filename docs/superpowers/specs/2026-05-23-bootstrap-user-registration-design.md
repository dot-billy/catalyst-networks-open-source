# Bootstrap User Registration Design

Date: 2026-05-23
Plane issue: not mapped for `catalyst-networks-open-source`
Branch: main

## Goal

Prevent random public account creation in the OSS Catalyst instance while keeping first-run
setup self-service for a new installer.

The first account on a fresh database should be able to register from the web UI. After
that account exists, anonymous registration should close unless the request is backed by
a valid organization invitation or an explicit public-registration setting.

## Current Behavior

`/register/` is public. It creates a normal user from email and password, logs the user in,
and redirects to the dashboard. Any authenticated user can then create an organization and
is added as the organization's `owner`.

The application already has organization invitations, but invitation acceptance currently
assumes the invitee can log in first. If public registration is closed without changing
the invitation flow, invited users without accounts will have no supported way to create
their account.

## Approved Approach

Use a bootstrap exception plus invite-only registration after bootstrap:

- When there are zero users and bootstrap registration is enabled, `/register/` shows a
  first-admin form.
- Submitting the first-admin form creates the user as active and staff, logs them in, and
  redirects them to the dashboard.
- After any user exists, `/register/` no longer permits unauthenticated open signup by
  default.
- Existing organization invitations become the normal account creation path after
  bootstrap. A valid invitation token can open a locked registration form for the invited
  email address.
- Deployments that intentionally want open signup can opt in through configuration.

## Configuration

Add two settings loaded from environment variables:

- `ALLOW_BOOTSTRAP_REGISTRATION`, default `True`.
- `ALLOW_PUBLIC_REGISTRATION`, default `False`.

Behavior matrix:

| Users exist? | Invitation token valid? | `ALLOW_PUBLIC_REGISTRATION` | `ALLOW_BOOTSTRAP_REGISTRATION` | Result |
| --- | --- | --- | --- | --- |
| No | No | False | True | Allow first-admin bootstrap registration |
| No | No | False | False | Block registration and tell operator to create a superuser |
| Yes | No | False | Any | Block registration and direct user to ask for an invitation |
| Any | Yes | False | Any | Allow invite-gated registration for the invited email |
| Any | Any | True | Any | Allow public registration as the current app does |

The default OSS experience is secure enough for internet exposure after bootstrap while
remaining easy to install locally.

## User Flows

### First Installer

1. Installer starts the Compose stack on a fresh database.
2. Installer visits `/register/`.
3. The page title and copy identify the action as first-admin setup.
4. Installer enters email and password.
5. The app creates the first user with `is_staff=True`, logs them in, and redirects to
   `/dashboard/`.
6. The dashboard still guides the user to create the first organization. Organization
   creation keeps the current behavior: the creator becomes `owner`.

The bootstrap form does not create an organization automatically. Keeping organization
creation as the next explicit step preserves the current setup choices for CIDR, CA, and
lighthouse creation.

### Public Registration After Bootstrap

1. Anonymous visitor opens `/register/` after at least one user exists.
2. With default settings, the app does not render a signup form.
3. The page explains that account creation is invitation-only and links to login.
4. The login page hides the "Create one" public signup link when open registration is not
   available.

The blocked page must not disclose user counts beyond generic setup state. It should say
registration is closed, not "there are already N users."

### Invited User Without An Account

1. An owner or admin invites an email address through the existing organization member
   flow.
2. The email link points to the existing invitation accept URL.
3. If the invitee is anonymous and the invitation is valid, the accept view redirects to
   `/register/?invitation=<token>`.
4. The registration form locks the email field to the invitation email and asks only for
   password confirmation.
5. On success, the app creates the user, accepts the invitation in the same transaction,
   logs the user in, and redirects to the organization detail page.

This token-gated path is allowed even when public registration is disabled.

### Invited User With An Existing Account

1. The invitee opens the invitation link.
2. If anonymous, they are sent to login with `next` pointing back to the invitation URL.
3. Once logged in, the app verifies that the authenticated email matches the invitation
   email.
4. The invitation is accepted and membership is created with the invited role.

The current email-match protection remains required.

## Authorization And Security

- First-admin bootstrap eligibility is based on the database having zero users.
- First-admin creation must happen in an atomic transaction to reduce the chance of two
  simultaneous first users. The implementation should re-check the user count inside the
  transaction before saving.
- Invite-gated registration must only accept pending, unexpired invitations.
- Invite-gated registration must ignore posted email values and use the invitation email.
- Invitation acceptance must create membership only after authentication or after
  successful token-gated account creation.
- Expired, revoked, accepted, unknown, or email-mismatched invitations must not create
  users or memberships.
- Public registration opt-in must be explicit through `ALLOW_PUBLIC_REGISTRATION=True`.

## UI And Copy

Reuse the existing auth shell and form styling.

Login page:

- Show "Create one" only if registration is available because public registration is
  enabled or because no users exist and bootstrap registration is enabled.
- If registration is closed, replace the signup prompt with short copy such as "Need
  access? Ask an organization owner for an invitation."

Registration page modes:

- `bootstrap`: title "Create first admin"; copy explains this account will initialize
  the instance.
- `public`: current generic "Create account" behavior.
- `invitation`: title "Accept invitation"; show the organization name and locked invited
  email.
- `closed`: no form; show invitation-only copy and a login link.

## Code Boundaries

Keep registration policy logic out of templates by adding a small helper in the users app.

Expected responsibilities:

- `users/registration_policy.py`: decide whether registration is available, classify
  registration mode, validate invitation tokens for registration, and centralize setting
  checks.
- `users/forms.py`: add form support for bootstrap/public registration and invite-gated
  registration.
- `users/views.py`: apply the policy in `register_view`, perform atomic account creation,
  and continue blocking API registration.
- `organizations/views.py`: adjust invitation acceptance so anonymous valid invitees can
  reach the invite-gated registration path.
- `templates/base/login.html` and `templates/base/register.html`: render the policy-driven
  copy and form states.
- `.env.example`, `.env.prod.example`, README, and in-app getting started docs: document
  the bootstrap defaults and how to disable bootstrap or enable public registration.

## Testing

Add or update Django tests for:

- Fresh database: `GET /register/` renders bootstrap registration.
- Fresh database: valid bootstrap `POST /register/` creates a user with `is_staff=True`
  and redirects to dashboard.
- Existing user: default `GET /register/` renders closed registration.
- Existing user: default `POST /register/` does not create a new user.
- `ALLOW_PUBLIC_REGISTRATION=True`: existing-user `POST /register/` creates a normal
  non-staff user as today.
- `ALLOW_BOOTSTRAP_REGISTRATION=False`: zero-user `GET /register/` renders closed
  registration.
- Login page shows or hides the public signup prompt based on the same policy.
- Anonymous valid invitation opens invite-gated registration.
- Invite-gated registration creates the invited user, accepts the invitation, and creates
  the membership.
- Invite-gated registration rejects expired, revoked, unknown, and email-mismatched token
  attempts.
- Existing-account invitation acceptance still requires matching authenticated email.

## Documentation

Update setup docs to explain the default path:

1. Start services.
2. Visit `/register/` to create the first admin, or run `createsuperuser` if bootstrap
   registration is disabled.
3. Create the first organization.
4. Invite additional users from organization member management.

The docs should clearly distinguish user account registration from node registration
tokens so operators do not confuse `REGISTRATION_MASTER_TOKEN` with human signup.

## Risks

- Race conditions during first-user creation could allow two bootstrap accounts if the
  count is checked only before the save.
- Closing registration without invite-gated account creation would break the existing
  invitation experience for new users.
- Hiding the signup link only in templates is insufficient; the view must enforce the
  policy on both GET and POST.
- Staff status for the first bootstrap user grants Django admin access. This is intended
  for the first installer, but docs should make the trust boundary clear.

## Out Of Scope

- Automatic organization creation during account bootstrap.
- Email domain allowlists.
- Admin approval queues.
- Billing, plan limits, hosted-service license gates, or multi-tenant commercial signup.
- Changing node registration token behavior.
