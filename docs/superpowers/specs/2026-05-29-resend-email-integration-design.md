# Resend Transactional Email Integration Design

## Goal

Add app-wide transactional email sending through Resend for the regular customer app and the open-source customer app while preserving the existing Django mail API call sites.

The integration should cover invitations, password reset mail, support ticket email, and event notification email wherever those flows exist in each repository.

## Current State

Both projects already send email through Django's `send_mail` and `EmailMessage` abstractions. The regular customer app additionally has support ticket emails and notification event emails. The open-source app currently has organization invitations and Django auth password reset routes, with Slack-style notification integrations but no org notification email sender.

Both settings modules currently default to Django SMTP and switch to Mailgun when `MAILGUN_API_KEY` and `MAILGUN_DOMAIN` are present.

## Recommended Approach

Use Django Anymail's Resend backend.

This keeps existing mail producers unchanged and centralizes provider selection in settings. Resend's Python SDK would require custom wrappers around Django's password reset and attachment-capable `EmailMessage` flows, while SMTP would be generic configuration rather than a first-class integration.

## Configuration

Add `django-anymail` to both projects.

Introduce these environment variables:

- `RESEND_API_KEY`: Resend API key with sending access.
- `DEFAULT_FROM_EMAIL`: sender address on a verified Resend domain.
- `EMAIL_BACKEND`: optional explicit override for local console, SMTP, or tests.

Provider precedence should be:

1. If `EMAIL_BACKEND` is set, use it exactly.
2. Else if `RESEND_API_KEY` is set, use `anymail.backends.resend.EmailBackend`.
3. Else if existing Mailgun settings are complete, keep the current Mailgun backend behavior.
4. Else fall back to Django SMTP.

Because the default examples currently set `EMAIL_BACKEND`, update them so Resend can activate from only `RESEND_API_KEY` plus `DEFAULT_FROM_EMAIL`. Keep commented examples for SMTP override.

## Data Flow

Existing application code continues to call Django mail APIs:

- Organization invitation emails call `send_mail`.
- Django auth password reset uses the configured Django email backend.
- Support ticket notification and auto-reply emails use `EmailMessage`.
- Regular-app event notification emails call `send_mail`.

The selected backend sends the message through Resend when `RESEND_API_KEY` is configured. No database model or migration is needed.

## Error Handling

Email senders keep their existing exception behavior. Tasks that already catch and log email failures continue to do so. Views that synchronously send invitation email should continue surfacing failures through their current message handling.

The implementation should not log Resend API keys or full provider responses that may include sensitive headers.

## Documentation

Update both README configuration tables and `.env.example` files with Resend setup notes:

- Create a Resend API key with sending access.
- Verify the sender domain in Resend.
- Set `RESEND_API_KEY`.
- Set `DEFAULT_FROM_EMAIL` to the verified sender.
- Leave `EMAIL_BACKEND` empty unless overriding the provider intentionally.

## Testing

Tests should verify:

- Settings select Anymail Resend when `RESEND_API_KEY` is present and `EMAIL_BACKEND` is unset.
- Explicit `EMAIL_BACKEND` still wins over Resend.
- Existing Mailgun fallback remains available when Resend is not configured.
- At least one existing email path still sends through Django's locmem backend in tests.

Use test-first implementation for behavior changes.

## Non-Goals

- No Resend webhooks or delivery status tracking.
- No per-organization Resend integration UI.
- No change to email templates.
- No direct use of the Resend Python SDK unless Anymail proves insufficient.
