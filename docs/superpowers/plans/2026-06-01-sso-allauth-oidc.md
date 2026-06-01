# SSO Allauth OIDC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the approved organization-admin SSO settings UI and extend SSO from SAML-only to SAML plus django-allauth-backed Google Workspace and generic OIDC, without weakening existing org scoping, RBAC, or SAML behavior.

**Architecture:** Keep Catalyst as the source of truth for organization ownership, provider selection, provisioning rules, and SSO enforcement. Use django-allauth only for OAuth/OIDC protocol handling, token exchange, provider callbacks, and normalized social identity capture. Existing SAML flows remain in `sso/views.py`; OIDC and Google flows enter through Catalyst org-scoped routes that seed session context and then delegate to allauth. A Catalyst allauth adapter completes the login only after org, hosted-domain, issuer, membership, and provisioning checks pass.

**Tech Stack:** Django 5.2, django-allauth, python3-saml, django-axes, HTMX, Tailwind, Catalyst template components, encrypted model secrets using the existing `FIELD_ENCRYPTION_KEY` convention.

---

## Scope And Constraints

- Implement this plan inside `/home/uwadmin/Development/catalyst-networks-open-source`.
- Preserve the current SAML login, ACS, metadata, configuration, and toggle routes.
- Add Google Workspace and generic OIDC as SSO provider modes; do not hand-roll OAuth/OIDC callbacks.
- Keep SSO settings visible only to organization owners and admins.
- Keep non-admin members out of SSO configuration and persistent SSO navigation.
- Store OIDC client secrets encrypted and never render existing secret values back into forms.
- Keep machine-facing node APIs unchanged.

## File Structure

Modify these files:

- `requirements.txt` - add `django-allauth`.
- `open_cvpn/settings.py` - add allauth apps, backend, adapter, middleware/settings required by the installed allauth version, and provider defaults.
- `open_cvpn/urls.py` - include allauth URLs under an internal path.
- `sso/models.py` - extend `SSOConfiguration` with provider type, OIDC fields, encrypted secret helpers, and allauth app sync metadata.
- `sso/forms.py` - replace the SAML-only configuration form with a provider-aware form.
- `sso/views.py` - keep SAML behavior and add provider-aware login branching plus OIDC initiation.
- `sso/urls.py` - add OIDC initiation and preserve existing canonical paths.
- `sso/policies.py` - keep enforcement protocol-neutral.
- `sso/templates/sso/configure.html` - add provider selection and OIDC/Google fields.
- `templates/base/base.html` - add persistent org SSO nav item for owners/admins.
- `templates/components/mobile_nav.html` - add mobile SSO nav item for owners/admins.
- `templates/organizations/detail.html` - add admin-only Resource Shortcuts SSO card.
- `templates/base/login.html` - keep the org-slug SSO entry and make it provider-neutral.
- `sso/tests.py` - extend existing SAML tests with provider-aware regression tests.
- `organizations/tests.py` - extend org shell tests for SSO visibility.

Create these files:

- `sso/services.py` - shared SSO provisioning, identity validation, allauth SocialApp synchronization, and secret encryption helpers.
- `sso/adapters.py` - Catalyst allauth social account adapter.
- `sso/tests/test_allauth_oidc.py` - OIDC/Google focused tests.
- `sso/tests/test_sso_ui.py` - SSO navigation and configuration UI tests if splitting the current single `sso/tests.py` is clean in this app.

## Task 1: Add django-allauth Wiring Under Tests

- [ ] Add a settings regression test before changing settings.

  Add to `sso/tests/test_allauth_oidc.py` or the existing `sso/tests.py` if the app is still module-based:

  ```python
  from django.conf import settings
  from django.test import SimpleTestCase
  from django.urls import reverse


  class AllauthWiringTests(SimpleTestCase):
      def test_allauth_is_configured_for_catalyst_sso(self):
          self.assertIn("allauth", settings.INSTALLED_APPS)
          self.assertIn("allauth.socialaccount", settings.INSTALLED_APPS)
          self.assertIn("allauth.socialaccount.providers.google", settings.INSTALLED_APPS)
          self.assertIn("allauth.socialaccount.providers.openid_connect", settings.INSTALLED_APPS)
          self.assertIn(
              "allauth.account.auth_backends.AuthenticationBackend",
              settings.AUTHENTICATION_BACKENDS,
          )
          self.assertEqual(
              settings.SOCIALACCOUNT_ADAPTER,
              "sso.adapters.CatalystSocialAccountAdapter",
          )

      def test_allauth_urls_are_mounted(self):
          self.assertEqual(reverse("socialaccount_connections"), "/accounts/social/connections/")
  ```

- [ ] Run the focused failing test.

  ```bash
  cd /home/uwadmin/Development/catalyst-networks-open-source
  docker compose run --rm web python manage.py test sso.tests.AllauthWiringTests
  ```

  Expected result: it fails because allauth is not installed/configured yet.

- [ ] Add `django-allauth` to `requirements.txt`.

  Use a compatible pinned version matching Django 5.2 support:

  ```text
  django-allauth==65.18.0
  ```

- [ ] Update `open_cvpn/settings.py`.

  Keep the existing axes and model backends. Add allauth after the Django model backend so password auth stays unchanged:

  ```python
  INSTALLED_APPS += [
      "django.contrib.sites",
      "allauth",
      "allauth.account",
      "allauth.socialaccount",
      "allauth.socialaccount.providers.google",
      "allauth.socialaccount.providers.openid_connect",
  ]

  SITE_ID = int(os.getenv("DJANGO_SITE_ID", "1"))

  AUTHENTICATION_BACKENDS = [
      "axes.backends.AxesStandaloneBackend",
      "django.contrib.auth.backends.ModelBackend",
      "allauth.account.auth_backends.AuthenticationBackend",
  ]

  SOCIALACCOUNT_ADAPTER = "sso.adapters.CatalystSocialAccountAdapter"
  SOCIALACCOUNT_AUTO_SIGNUP = False
  SOCIALACCOUNT_LOGIN_ON_GET = True
  SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
  ```

  If the installed allauth release requires `allauth.account.middleware.AccountMiddleware`, add it immediately after `AuthenticationMiddleware` in `MIDDLEWARE`.

- [ ] Add allauth URLs in `open_cvpn/urls.py`.

  ```python
  path("accounts/", include("allauth.urls")),
  ```

- [ ] Create a minimal adapter placeholder in `sso/adapters.py` so settings import cleanly.

  ```python
  from allauth.socialaccount.adapter import DefaultSocialAccountAdapter


  class CatalystSocialAccountAdapter(DefaultSocialAccountAdapter):
      pass
  ```

- [ ] Re-run the wiring test.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.AllauthWiringTests
  ```

  Expected result: the wiring test passes.

## Task 2: Extend The SSO Configuration Model

- [ ] Add model tests first.

  Add tests covering defaults, provider choices, OIDC validation, and encrypted secret behavior:

  ```python
  class SSOConfigurationProviderModelTests(TestCase):
      def test_defaults_remain_saml(self):
          config = SSOConfiguration.objects.create(
              organization=self.org,
              entity_id="https://idp.example.com/entity",
              sso_url="https://idp.example.com/sso",
              x509_cert=self.cert,
          )

          self.assertEqual(config.provider_type, SSOConfiguration.PROVIDER_SAML)
          self.assertFalse(config.is_oidc)

      def test_oidc_secret_is_encrypted(self):
          config = SSOConfiguration.objects.create(
              organization=self.org,
              provider_type=SSOConfiguration.PROVIDER_OIDC,
              oidc_mode=SSOConfiguration.OIDC_GENERIC,
              oidc_display_name="Okta",
              oidc_issuer_url="https://okta.example.com/oauth2/default",
              oidc_client_id="client-id",
          )

          config.set_oidc_client_secret("plain-secret")
          config.save(update_fields=["oidc_client_secret_encrypted"])
          config.refresh_from_db()

          self.assertNotIn("plain-secret", config.oidc_client_secret_encrypted)
          self.assertEqual(config.get_oidc_client_secret(), "plain-secret")
  ```

- [ ] Run the focused failing test.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOConfigurationProviderModelTests
  ```

  Expected result: it fails because fields and helpers do not exist.

- [ ] Update `sso/models.py`.

  Add fields without breaking existing SAML rows:

  ```python
  PROVIDER_SAML = "saml"
  PROVIDER_OIDC = "oidc"
  PROVIDER_CHOICES = [
      (PROVIDER_SAML, "SAML"),
      (PROVIDER_OIDC, "OIDC / Google"),
  ]

  OIDC_GOOGLE = "google"
  OIDC_GENERIC = "generic"
  OIDC_MODE_CHOICES = [
      (OIDC_GOOGLE, "Google Workspace"),
      (OIDC_GENERIC, "Generic OIDC"),
  ]

  provider_type = models.CharField(
      max_length=20,
      choices=PROVIDER_CHOICES,
      default=PROVIDER_SAML,
  )
  oidc_mode = models.CharField(
      max_length=20,
      choices=OIDC_MODE_CHOICES,
      blank=True,
      default="",
  )
  oidc_display_name = models.CharField(max_length=120, blank=True)
  oidc_issuer_url = models.URLField(blank=True)
  oidc_client_id = models.CharField(max_length=255, blank=True)
  oidc_client_secret_encrypted = models.TextField(blank=True)
  oidc_provider_id = models.SlugField(max_length=80, blank=True)
  oidc_allowed_domain = models.CharField(max_length=255, blank=True)
  oidc_scopes = models.CharField(max_length=255, default="openid email profile")
  oidc_email_claim = models.CharField(max_length=80, default="email")
  oidc_first_name_claim = models.CharField(max_length=80, default="given_name")
  oidc_last_name_claim = models.CharField(max_length=80, default="family_name")
  oidc_subject_claim = models.CharField(max_length=80, default="sub")
  allauth_app_id = models.PositiveIntegerField(null=True, blank=True)
  ```

  Add convenience properties:

  ```python
  @property
  def is_saml(self):
      return self.provider_type == self.PROVIDER_SAML

  @property
  def is_oidc(self):
      return self.provider_type == self.PROVIDER_OIDC
  ```

- [ ] Add secret helpers in `sso/services.py` and call them from model methods.

  ```python
  from cryptography.fernet import Fernet
  from django.conf import settings
  from django.core.exceptions import ImproperlyConfigured


  def get_sso_fernet():
      key = getattr(settings, "FIELD_ENCRYPTION_KEY", "")
      if not key:
          raise ImproperlyConfigured("FIELD_ENCRYPTION_KEY is required for OIDC SSO secrets")
      return Fernet(key.encode() if isinstance(key, str) else key)


  def encrypt_sso_secret(value):
      if not value:
          return ""
      return get_sso_fernet().encrypt(value.encode()).decode()


  def decrypt_sso_secret(value):
      if not value:
          return ""
      return get_sso_fernet().decrypt(value.encode()).decode()
  ```

- [ ] Create and inspect the migration.

  ```bash
  docker compose run --rm web python manage.py makemigrations sso
  docker compose run --rm web python manage.py migrate
  ```

  Expected result: a migration adds nullable or defaulted fields without requiring data prompts.

- [ ] Re-run model tests and existing SAML tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOConfigurationProviderModelTests sso.tests.SAMLSettingsTests
  ```

  Expected result: provider model tests and existing SAML settings tests pass.

## Task 3: Add Protocol-Neutral SSO Identity Services

- [ ] Write service tests before refactoring SAML or adding OIDC.

  Cover member login, auto-provision, hosted domain rejection, disabled auto-provision, and missing email:

  ```python
  class CompleteSSOLoginTests(TestCase):
      def test_existing_member_can_complete_sso_login(self):
          identity = SSOLoginIdentity(
              email=self.admin.email,
              subject="abc123",
              first_name="Ada",
              last_name="Lovelace",
              provider="saml",
          )

          user = complete_sso_login(self.config, identity)

          self.assertEqual(user, self.admin)

      def test_oidc_hosted_domain_is_enforced(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_OIDC
          self.config.oidc_allowed_domain = "example.com"
          self.config.save()
          identity = SSOLoginIdentity(
              email="person@other.com",
              subject="abc123",
              provider="google",
          )

          with self.assertRaises(SSOLoginRejected):
              complete_sso_login(self.config, identity)
  ```

- [ ] Run the focused failing test.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.CompleteSSOLoginTests
  ```

  Expected result: it fails because the service does not exist.

- [ ] Implement `sso/services.py`.

  Add a small identity dataclass and protocol-neutral completion function:

  ```python
  from dataclasses import dataclass


  class SSOLoginRejected(Exception):
      pass


  @dataclass(frozen=True)
  class SSOLoginIdentity:
      email: str
      subject: str
      provider: str
      first_name: str = ""
      last_name: str = ""


  def complete_sso_login(config, identity):
      email = (identity.email or "").strip().lower()
      if not email:
          raise SSOLoginRejected("The identity provider did not return an email address.")

      if config.is_oidc and config.oidc_allowed_domain:
          domain = email.rsplit("@", 1)[-1]
          if domain.lower() != config.oidc_allowed_domain.lower():
              raise SSOLoginRejected("This email domain is not allowed for this organization.")

      # Existing member lookup, auto-create, role assignment, and org membership
      # use the current SAML ACS behavior as the behavioral source of truth.
  ```

  Move user lookup, auto-create, membership creation, and role assignment from `sso_acs` into this function. Keep existing audit/logging behavior but never log SAML assertions, OIDC tokens, or client secrets.

- [ ] Refactor `sso/views.py` SAML ACS to call `complete_sso_login`.

  Keep the current SAML response validation and only replace duplicated user provisioning logic:

  ```python
  identity = SSOLoginIdentity(
      email=email,
      subject=name_id,
      first_name=first_name,
      last_name=last_name,
      provider="saml",
  )
  user = complete_sso_login(config, identity)
  login(request, user)
  ```

- [ ] Re-run service tests and SAML ACS tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.CompleteSSOLoginTests sso.tests.SSOACSTests
  ```

  Expected result: new service tests and current SAML ACS tests pass.

## Task 4: Add Allauth App Sync And Catalyst Adapter

- [ ] Write tests for allauth SocialApp synchronization.

  ```python
  class AllauthSocialAppSyncTests(TestCase):
      def test_google_config_creates_google_social_app(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_OIDC
          self.config.oidc_mode = SSOConfiguration.OIDC_GOOGLE
          self.config.oidc_client_id = "google-client-id"
          self.config.set_oidc_client_secret("google-secret")
          self.config.save()

          app = sync_allauth_app_for_config(self.config)

          self.assertEqual(app.provider, "google")
          self.assertEqual(app.client_id, "google-client-id")
          self.assertEqual(app.secret, "google-secret")

      def test_generic_oidc_config_creates_openid_connect_social_app(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_OIDC
          self.config.oidc_mode = SSOConfiguration.OIDC_GENERIC
          self.config.oidc_display_name = "Okta"
          self.config.oidc_issuer_url = "https://okta.example.com/oauth2/default"
          self.config.oidc_client_id = "okta-client-id"
          self.config.set_oidc_client_secret("okta-secret")
          self.config.save()

          app = sync_allauth_app_for_config(self.config)

          self.assertEqual(app.provider, "openid_connect")
          self.assertEqual(app.provider_id, f"org-{self.org.slug}")
          self.assertEqual(app.client_id, "okta-client-id")
          self.assertEqual(app.settings["server_url"], self.config.oidc_issuer_url)
  ```

- [ ] Write adapter tests using a request factory and mocked social login.

  Cover missing org session context, disabled config, hosted domain rejection, and successful completion:

  ```python
  class CatalystSocialAccountAdapterTests(TestCase):
      def test_pre_social_login_rejects_missing_org_context(self):
          request = self.factory.get("/accounts/google/login/callback/")
          request.session = {}

          with self.assertRaises(ImmediateHttpResponse):
              CatalystSocialAccountAdapter().pre_social_login(request, self.sociallogin)
  ```

- [ ] Run the focused failing tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.AllauthSocialAppSyncTests sso.tests.CatalystSocialAccountAdapterTests
  ```

  Expected result: they fail because sync and adapter logic are not implemented.

- [ ] Implement `sync_allauth_app_for_config` in `sso/services.py`.

  ```python
  from allauth.socialaccount.models import SocialApp
  from django.contrib.sites.models import Site


  def sync_allauth_app_for_config(config):
      if not config.is_oidc:
          raise SSOLoginRejected("Allauth app sync is only valid for OIDC configurations.")

      provider = "google" if config.oidc_mode == config.OIDC_GOOGLE else "openid_connect"
      provider_id = ""
      if provider == "openid_connect":
          provider_id = config.oidc_provider_id or f"org-{config.organization.slug}"
      name = f"{config.organization.slug}:{config.oidc_display_name or config.get_oidc_mode_display()}"
      defaults = {
          "provider": provider,
          "provider_id": provider_id,
          "name": name,
          "client_id": config.oidc_client_id,
          "secret": config.get_oidc_client_secret(),
          "settings": {},
      }
      if provider == "openid_connect":
          defaults["settings"] = {
              "server_url": config.oidc_issuer_url,
              "fetch_userinfo": True,
              "oauth_pkce_enabled": True,
              "uid_field": config.oidc_subject_claim,
          }

      app, _ = SocialApp.objects.update_or_create(
          id=config.allauth_app_id,
          defaults=defaults,
      )
      app.sites.set([Site.objects.get_current()])
      if config.allauth_app_id != app.id or config.oidc_provider_id != provider_id:
          config.allauth_app_id = app.id
          config.oidc_provider_id = provider_id
          config.save(update_fields=["allauth_app_id", "oidc_provider_id", "updated_at"])
      return app
  ```

- [ ] Implement `CatalystSocialAccountAdapter` in `sso/adapters.py`.

  ```python
  from allauth.core.exceptions import ImmediateHttpResponse
  from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
  from django.contrib import messages
  from django.shortcuts import redirect

  from .models import SSOConfiguration
  from .services import SSOLoginIdentity, SSOLoginRejected, complete_sso_login


  class CatalystSocialAccountAdapter(DefaultSocialAccountAdapter):
      def pre_social_login(self, request, sociallogin):
          slug = request.session.get("sso_org_slug")
          if not slug:
              return

          try:
              config = SSOConfiguration.objects.select_related("organization").get(
                  organization__slug=slug,
                  provider_type=SSOConfiguration.PROVIDER_OIDC,
                  is_enabled=True,
              )
              extra = sociallogin.account.extra_data or {}
              identity = SSOLoginIdentity(
                  email=extra.get(config.oidc_email_claim, ""),
                  subject=extra.get(config.oidc_subject_claim, sociallogin.account.uid),
                  first_name=extra.get(config.oidc_first_name_claim, ""),
                  last_name=extra.get(config.oidc_last_name_claim, ""),
                  provider=sociallogin.account.provider,
              )
              user = complete_sso_login(config, identity)
          except (SSOConfiguration.DoesNotExist, SSOLoginRejected) as exc:
              messages.error(request, str(exc))
              raise ImmediateHttpResponse(redirect("login"))

          sociallogin.user = user
  ```

  Preserve allauth account-linking safety: do not silently attach arbitrary social accounts to unrelated users outside the organization SSO flow.

- [ ] Re-run allauth sync and adapter tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.AllauthSocialAppSyncTests sso.tests.CatalystSocialAccountAdapterTests
  ```

  Expected result: sync and adapter tests pass.

## Task 5: Add Provider-Aware Login Routes

- [ ] Add route tests first.

  Cover SAML still entering old flow and OIDC redirecting through allauth:

  ```python
  class SSOProviderLoginRoutingTests(TestCase):
      def test_saml_login_uses_existing_saml_flow(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_SAML
          self.config.save(update_fields=["provider_type"])

          response = self.client.get(reverse("sso:login", args=[self.org.slug]))

          self.assertEqual(response.status_code, 302)
          self.assertIn("SAMLRequest", response["Location"])

      def test_oidc_login_sets_org_context_and_redirects(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_OIDC
          self.config.oidc_mode = SSOConfiguration.OIDC_GOOGLE
          self.config.oidc_client_id = "client-id"
          self.config.set_oidc_client_secret("client-secret")
          self.config.save()

          response = self.client.get(reverse("sso:login", args=[self.org.slug]))

          self.assertEqual(response.status_code, 302)
          self.assertEqual(self.client.session["sso_org_slug"], self.org.slug)
  ```

- [ ] Run the focused failing tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOProviderLoginRoutingTests
  ```

  Expected result: OIDC branch fails before implementation.

- [ ] Update `sso/urls.py`.

  Add the explicit OIDC initiation route:

  ```python
  path("<slug:slug>/oidc/login/", views.oidc_login, name="oidc_login"),
  ```

- [ ] Update `sso/views.py`.

  Keep `sso_login` as the canonical provider-neutral route:

  ```python
  def sso_login(request, slug):
      config = get_object_or_404(
          SSOConfiguration.objects.select_related("organization"),
          organization__slug=slug,
          is_enabled=True,
      )
      if config.is_oidc:
          return oidc_login(request, slug)
      return saml_login(request, slug, config=config)
  ```

  Extract the current SAML body into `saml_login(request, slug, config=None)` so SAML behavior remains unchanged.

  Add OIDC initiation:

  ```python
  def oidc_login(request, slug):
      config = get_object_or_404(
          SSOConfiguration.objects.select_related("organization"),
          organization__slug=slug,
          provider_type=SSOConfiguration.PROVIDER_OIDC,
          is_enabled=True,
      )
      sync_allauth_app_for_config(config)
      request.session["sso_org_slug"] = slug
      request.session["sso_next"] = _safe_return_url(request.GET.get("next"))
      if config.oidc_mode == SSOConfiguration.OIDC_GOOGLE:
          return redirect("/accounts/google/login/?process=login")
      return redirect(f"/accounts/oidc/{config.oidc_provider_id}/login/?process=login")
  ```

  Prefer allauth URL reversing if the installed provider exposes a named login URL; keep the test asserting behavior rather than an exact private allauth name.

- [ ] Re-run route tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOProviderLoginRoutingTests sso.tests.SSOLoginEnforcementTests
  ```

  Expected result: provider routing and existing SSO login enforcement tests pass.

## Task 6: Build Provider-Aware Configuration UI

- [ ] Add form and view tests first.

  Cover admin access, member denial, SAML form rendering, Google form rendering, generic OIDC rendering, and secret preservation:

  ```python
  class SSOConfigurationProviderFormTests(TestCase):
      def test_owner_can_save_google_oidc_settings(self):
          self.client.force_login(self.owner)
          response = self.client.post(
              reverse("sso:configure", args=[self.org.slug]),
              {
                  "provider_type": SSOConfiguration.PROVIDER_OIDC,
                  "oidc_mode": SSOConfiguration.OIDC_GOOGLE,
                  "oidc_display_name": "Google Workspace",
                  "oidc_client_id": "client-id",
                  "oidc_client_secret": "client-secret",
                  "oidc_allowed_domain": "example.com",
                  "default_role": "member",
                  "is_enabled": "on",
              },
          )

          self.assertEqual(response.status_code, 302)
          self.config.refresh_from_db()
          self.assertTrue(self.config.is_oidc)
          self.assertEqual(self.config.get_oidc_client_secret(), "client-secret")
  ```

- [ ] Run the focused failing tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOConfigurationProviderFormTests
  ```

  Expected result: new provider fields are not rendered or saved yet.

- [ ] Update `sso/forms.py`.

  Replace the SAML-only form with one provider-aware form. Keep SAML fields required only when `provider_type == "saml"` and OIDC fields required only when `provider_type == "oidc"`:

  ```python
  oidc_client_secret = forms.CharField(
      required=False,
      widget=forms.PasswordInput(render_value=False),
      help_text="Leave blank to keep the existing client secret.",
  )

  def clean(self):
      cleaned = super().clean()
      provider_type = cleaned.get("provider_type")
      if provider_type == SSOConfiguration.PROVIDER_SAML:
          self._require(cleaned, "entity_id")
          self._require(cleaned, "sso_url")
          self._require(cleaned, "x509_cert")
      if provider_type == SSOConfiguration.PROVIDER_OIDC:
          self._require(cleaned, "oidc_mode")
          self._require(cleaned, "oidc_client_id")
          if not self.instance.pk and not cleaned.get("oidc_client_secret"):
              self.add_error("oidc_client_secret", "Client secret is required.")
          if cleaned.get("oidc_mode") == SSOConfiguration.OIDC_GENERIC:
              self._require(cleaned, "oidc_issuer_url")
      return cleaned
  ```

  In `save`, call `instance.set_oidc_client_secret()` only when a new secret was submitted.

- [ ] Update `sso/views.py` configuration handling.

  Keep the existing owner/admin authorization and messages. After saving OIDC settings, call `sync_allauth_app_for_config(config)` so invalid credentials surface early.

- [ ] Update `sso/templates/sso/configure.html`.

  Use the approved persistent-access design and add one settings surface:

  - Provider segmented choice: SAML, Google Workspace, Generic OIDC.
  - Shared controls: enabled, enforce SSO, auto-create users, default role.
  - SAML panel: entity ID, SSO URL, x509 certificate, metadata URL.
  - Google panel: client ID, client secret, hosted domain, callback URL.
  - Generic OIDC panel: display name, issuer/discovery URL, client ID, client secret, scopes, claim mapping, callback URL.

  Keep callback URLs copyable and label them as identity-provider callback URLs. The Catalyst `/sso/<org-slug>/oidc/login/` route is only the initiation route.

  ```django
  Google callback:
  {{ request.scheme }}://{{ request.get_host }}/accounts/google/login/callback/

  Generic OIDC callback:
  {{ request.scheme }}://{{ request.get_host }}/accounts/oidc/{{ form.instance.oidc_provider_id }}/login/callback/
  ```

  Render all provider sections server-side and use a small progressive-enhancement script only to hide inactive sections.

- [ ] Re-run form and existing configure tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOConfigurationProviderFormTests sso.tests.SAMLSettingsTests
  ```

  Expected result: provider-aware config tests pass and existing SAML configure behavior remains intact.

## Task 7: Add SSO Discoverability To Org UI

- [ ] Add UI tests first.

  Extend `organizations/tests.py` or `sso/tests/test_sso_ui.py`:

  ```python
  class SSOSettingsNavigationTests(TestCase):
      def test_owner_sees_sso_nav_and_shortcut(self):
          self.client.force_login(self.owner)
          response = self.client.get(reverse("organizations:detail", args=[self.org.pk]))

          self.assertContains(response, "SSO")
          self.assertContains(response, reverse("sso:configure", args=[self.org.slug]))

      def test_member_does_not_see_sso_nav_or_shortcut(self):
          self.client.force_login(self.member)
          response = self.client.get(reverse("organizations:detail", args=[self.org.pk]))

          self.assertNotContains(response, reverse("sso:configure", args=[self.org.slug]))
  ```

- [ ] Run the focused failing tests.

  ```bash
  docker compose run --rm web python manage.py test organizations.tests.SSOSettingsNavigationTests
  ```

  Expected result: SSO nav/shortcut visibility fails before template updates.

- [ ] Update `templates/base/base.html`.

  Add SSO after Members and before Webhooks in the current organization nav, gated by the current `organization.role` value:

  ```django
  {% if organization.role == 'owner' or organization.role == 'admin' %}
      <a href="{% url 'sso:configure' organization.slug %}" class="catalyst-menu-link {% if '/sso/' in request.path %}active{% endif %}">
          SSO
      </a>
  {% endif %}
  ```

  Use the existing nav item classes and active-state pattern. Do not introduce a new visual style.

- [ ] Update `templates/components/mobile_nav.html`.

  Add the same gated SSO item in the mobile org menu after Members and before Webhooks.

- [ ] Update `templates/organizations/detail.html`.

  Add an admin-only Resource Shortcuts tile:

  ```django
  {% if membership.role == 'owner' or membership.role == 'admin' %}
      <a href="{% url 'sso:configure' organization.slug %}" class="ops-resource-card">
          <span>SSO Settings</span>
          <span>Configure SAML, Google, or OIDC sign-in</span>
      </a>
  {% endif %}
  ```

  Reuse the existing Resource Shortcuts card pattern. Keep the existing header SSO Settings button.

- [ ] Re-run UI tests.

  ```bash
  docker compose run --rm web python manage.py test organizations.tests.SSOSettingsNavigationTests
  ```

  Expected result: owner/admin can see SSO settings entry points; member cannot.

## Task 8: Keep The Login Page Provider-Neutral

- [ ] Add login-page tests first.

  Cover that the public login SSO slug form still posts/redirects to the canonical provider-neutral SSO route and copy does not say SAML-only.

  ```python
  class PublicLoginSSOEntryTests(TestCase):
      def test_login_page_uses_provider_neutral_sso_copy(self):
          response = self.client.get(reverse("login"))

          self.assertContains(response, "Continue with SSO")
          self.assertNotContains(response, "SAML-only")
  ```

- [ ] Run the focused test.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.PublicLoginSSOEntryTests
  ```

  Expected result: it fails only if existing copy is SAML-specific or route assumptions changed.

- [ ] Update `templates/base/login.html`.

  Keep the slug-driven JavaScript redirect, but ensure it targets `/sso/<slug>/login/` and uses provider-neutral copy:

  ```javascript
  window.location.href = `/sso/${encodeURIComponent(orgSlug)}/login/`;
  ```

- [ ] Re-run login tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.PublicLoginSSOEntryTests sso.tests.SSOLoginEnforcementTests
  ```

  Expected result: login entry and SSO enforcement tests pass.

## Task 9: Verify Enforcement And Security Regressions

- [ ] Add/extend enforcement tests for both provider types.

  ```python
  class SSOProviderEnforcementTests(TestCase):
      def test_enforced_saml_blocks_password_login(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_SAML
          self.config.enforce_sso = True
          self.config.is_enabled = True
          self.config.save()

          config = get_enforced_sso_config(self.user)

          self.assertEqual(config, self.config)

      def test_enforced_oidc_blocks_password_login(self):
          self.config.provider_type = SSOConfiguration.PROVIDER_OIDC
          self.config.oidc_mode = SSOConfiguration.OIDC_GOOGLE
          self.config.enforce_sso = True
          self.config.is_enabled = True
          self.config.save()

          config = get_enforced_sso_config(self.user)

          self.assertEqual(config, self.config)
  ```

- [ ] Run the focused enforcement tests.

  ```bash
  docker compose run --rm web python manage.py test sso.tests.SSOProviderEnforcementTests sso.tests.SSOLoginEnforcementTests
  ```

  Expected result: SAML and OIDC enforcement both block password login when enabled.

- [ ] Review secret handling.

  Inspect rendered configure HTML and logs from failed form submissions. Confirm these strings do not appear:

  - OIDC client secret value.
  - OAuth access token.
  - OAuth refresh token.
  - ID token.
  - SAML assertion body.

- [ ] Add regression tests if any secret appears in a response body.

## Task 10: Full Verification

- [ ] Run migrations from a clean app container.

  ```bash
  docker compose run --rm web python manage.py migrate
  ```

  Expected result: all migrations apply successfully.

- [ ] Run targeted SSO and organization tests.

  ```bash
  docker compose run --rm web python manage.py test sso organizations
  ```

  Expected result: all SSO and organization tests pass.

- [ ] Run the project test suite if targeted tests pass.

  ```bash
  docker compose run --rm web python manage.py test
  ```

  Expected result: the full Django test suite passes, or any unrelated pre-existing failures are captured with exact test names and failure summaries.

- [ ] Run Django system checks.

  ```bash
  docker compose run --rm web python manage.py check
  ```

  Expected result: no new system check errors.

- [ ] Inspect git diff.

  ```bash
  git diff --stat
  git diff --check
  ```

  Expected result: expected SSO/settings/template/test files changed; no whitespace errors; no unrelated scratch files staged.

## Manual Smoke Checklist

- [ ] Owner sees `SSO` in desktop organization nav between Members and Webhooks.
- [ ] Admin sees `SSO` in desktop and mobile organization nav.
- [ ] Member does not see SSO nav or shortcut.
- [ ] Owner can save existing SAML settings without entering OIDC fields.
- [ ] Owner can select Google Workspace, save client ID/secret/domain, and see secret masked afterward.
- [ ] Owner can select Generic OIDC, save issuer/client settings, and see callback URL.
- [ ] Public login slug form works for SAML orgs.
- [ ] Public login slug form works for OIDC orgs and redirects into allauth.
- [ ] Enforced SSO blocks password login for a member of an org using either SAML or OIDC.

## Self-Review Requirements

- [ ] Confirm every SAML test that existed before this work still passes.
- [ ] Confirm allauth is used for OIDC and Google protocol handling.
- [ ] Confirm Catalyst code, not allauth alone, enforces organization membership and provider constraints.
- [ ] Confirm OIDC secrets are encrypted at rest and never printed in forms, messages, logs, or tests.
- [ ] Confirm UI changes reuse existing Catalyst template patterns and do not create a separate SSO landing page.
