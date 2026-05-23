# Bootstrap User Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow first-run web bootstrap of the initial admin user, then close public registration and require invitations for additional users by default.

**Architecture:** Add a small `users.registration_policy` helper that classifies registration requests as `bootstrap`, `public`, `invitation`, or `closed`. Views enforce that policy on GET and POST; templates only render the resulting state. The existing organization invitation model becomes the token-gated account creation path for invited users without accounts.

**Tech Stack:** Django 5.2, Django auth custom email user model, Django TestCase, existing Django templates and Docker Compose test flow.

---

## File Structure

- Create `users/registration_policy.py`: central registration mode decisions, invitation token validation, and setting checks.
- Create `users/tests_registration_policy.py`: unit tests for registration policy modes.
- Create `users/tests_registration_flow.py`: web tests for `/register/`, login signup prompt, and invite-gated registration.
- Create `organizations/tests_invitation_registration.py`: web tests for invitation accept redirects and existing-account acceptance.
- Modify `open_cvpn/settings.py`: add `ALLOW_BOOTSTRAP_REGISTRATION` and `ALLOW_PUBLIC_REGISTRATION`.
- Modify `users/forms.py`: extend `UserRegistrationForm` for bootstrap and invitation modes.
- Modify `users/views.py`: enforce policy in `register_view`; create users and invitation memberships transactionally.
- Modify `organizations/views.py`: allow anonymous valid invitees to reach invite-gated registration or login.
- Modify `templates/base/register.html`: render bootstrap, public, invitation, and closed modes.
- Modify `templates/base/login.html`: hide public signup when registration is closed.
- Modify `.env.example`, `.env.prod.example`, `README.md`, and `templates/docs/getting_started.html`: document first-admin bootstrap and registration settings.

## Task 1: Add Registration Policy Tests

**Files:**
- Create: `users/tests_registration_policy.py`
- Later modify: `open_cvpn/settings.py`
- Later create: `users/registration_policy.py`

- [ ] **Step 1: Write the failing policy tests**

Create `users/tests_registration_policy.py` with this content:

```python
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from organizations.models import Invitation, Membership, Organization
from users.registration_policy import get_registration_state


User = get_user_model()


@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class RegistrationPolicyTests(TestCase):
    def create_owner_org(self):
        owner = User.objects.create_user(
            email="owner@example.test",
            password="StrongPassword123!",
        )
        organization = Organization.objects.create(
            name="Policy Org",
            created_by=owner,
        )
        Membership.objects.create(
            organization=organization,
            user=owner,
            role="owner",
        )
        return owner, organization

    def test_bootstrap_available_when_no_users_exist(self):
        state = get_registration_state()

        self.assertTrue(state.can_register)
        self.assertEqual(state.mode, "bootstrap")
        self.assertIsNone(state.invitation)

    def test_registration_closed_after_any_user_exists(self):
        User.objects.create_user(
            email="existing@example.test",
            password="StrongPassword123!",
        )

        state = get_registration_state()

        self.assertFalse(state.can_register)
        self.assertEqual(state.mode, "closed")
        self.assertIsNone(state.invitation)

    @override_settings(ALLOW_BOOTSTRAP_REGISTRATION=False)
    def test_bootstrap_can_be_disabled_even_when_no_users_exist(self):
        state = get_registration_state()

        self.assertFalse(state.can_register)
        self.assertEqual(state.mode, "closed")
        self.assertIsNone(state.invitation)

    @override_settings(ALLOW_PUBLIC_REGISTRATION=True)
    def test_public_registration_setting_overrides_existing_users(self):
        User.objects.create_user(
            email="existing@example.test",
            password="StrongPassword123!",
        )

        state = get_registration_state()

        self.assertTrue(state.can_register)
        self.assertEqual(state.mode, "public")
        self.assertIsNone(state.invitation)

    def test_valid_invitation_allows_invitation_registration(self):
        owner, organization = self.create_owner_org()
        invitation = Invitation.objects.create(
            organization=organization,
            email="invitee@example.test",
            inviter=owner,
            role="member",
        )

        state = get_registration_state(invitation_token=invitation.token)

        self.assertTrue(state.can_register)
        self.assertEqual(state.mode, "invitation")
        self.assertEqual(state.invitation, invitation)

    @override_settings(ALLOW_PUBLIC_REGISTRATION=True)
    def test_valid_invitation_takes_precedence_over_public_registration(self):
        owner, organization = self.create_owner_org()
        invitation = Invitation.objects.create(
            organization=organization,
            email="invitee@example.test",
            inviter=owner,
            role="member",
        )

        state = get_registration_state(invitation_token=invitation.token)

        self.assertTrue(state.can_register)
        self.assertEqual(state.mode, "invitation")
        self.assertEqual(state.invitation, invitation)

    def test_expired_invitation_does_not_allow_registration(self):
        owner, organization = self.create_owner_org()
        invitation = Invitation.objects.create(
            organization=organization,
            email="invitee@example.test",
            inviter=owner,
            role="member",
        )
        invitation.expires_at = timezone.now() - timedelta(days=1)
        invitation.save(update_fields=["expires_at"])

        state = get_registration_state(invitation_token=invitation.token)

        self.assertFalse(state.can_register)
        self.assertEqual(state.mode, "closed")
        self.assertIsNone(state.invitation)
```

- [ ] **Step 2: Run tests to verify they fail because the helper does not exist**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_policy -v 2
```

Expected: FAIL with `ModuleNotFoundError: No module named 'users.registration_policy'`.

## Task 2: Implement Settings And Policy Helper

**Files:**
- Modify: `open_cvpn/settings.py`
- Create: `users/registration_policy.py`
- Test: `users/tests_registration_policy.py`

- [ ] **Step 1: Add boolean settings**

In `open_cvpn/settings.py`, after `STATIC_ASSET_VERSION = ...`, add:

```python
def _env_bool(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


ALLOW_BOOTSTRAP_REGISTRATION = _env_bool("ALLOW_BOOTSTRAP_REGISTRATION", True)
ALLOW_PUBLIC_REGISTRATION = _env_bool("ALLOW_PUBLIC_REGISTRATION", False)
```

- [ ] **Step 2: Create the registration policy helper**

Create `users/registration_policy.py` with this content:

```python
from dataclasses import dataclass
from typing import Optional

from django.conf import settings
from django.contrib.auth import get_user_model

from organizations.models import Invitation


@dataclass(frozen=True)
class RegistrationState:
    mode: str
    can_register: bool
    title: str
    subtitle: str
    submit_label: str = "Create account"
    invitation: Optional[Invitation] = None


def _public_registration_enabled():
    return getattr(settings, "ALLOW_PUBLIC_REGISTRATION", False)


def _bootstrap_registration_enabled():
    return getattr(settings, "ALLOW_BOOTSTRAP_REGISTRATION", True)


def get_valid_registration_invitation(invitation_token):
    if not invitation_token:
        return None

    try:
        invitation = Invitation.objects.select_related(
            "organization",
            "inviter",
        ).get(token=invitation_token)
    except Invitation.DoesNotExist:
        return None

    if not invitation.is_valid:
        return None

    return invitation


def get_registration_state(invitation_token=None):
    invitation = get_valid_registration_invitation(invitation_token)
    if invitation:
        return RegistrationState(
            mode="invitation",
            can_register=True,
            title="Accept invitation",
            subtitle=f"Create an account to join {invitation.organization.name}.",
            submit_label="Create account and join",
            invitation=invitation,
        )

    if _public_registration_enabled():
        return RegistrationState(
            mode="public",
            can_register=True,
            title="Create account",
            subtitle="Set up your catalyst_network workspace access.",
            submit_label="Create account",
        )

    user_exists = get_user_model().objects.exists()
    if _bootstrap_registration_enabled() and not user_exists:
        return RegistrationState(
            mode="bootstrap",
            can_register=True,
            title="Create first admin",
            subtitle="Initialize this Catalyst Networks instance with its first administrator account.",
            submit_label="Create first admin",
        )

    return RegistrationState(
        mode="closed",
        can_register=False,
        title="Registration is invitation-only",
        subtitle="Ask an organization owner or administrator for an invitation.",
    )


def public_signup_link_available():
    state = get_registration_state()
    return state.can_register and state.mode in {"bootstrap", "public"}
```

- [ ] **Step 3: Run policy tests**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_policy -v 2
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add open_cvpn/settings.py users/registration_policy.py users/tests_registration_policy.py
git commit -m "feat: add registration policy helper"
```

## Task 3: Extend Registration Form For Bootstrap And Invitation Modes

**Files:**
- Modify: `users/forms.py`
- Create: `users/tests_registration_flow.py`

- [ ] **Step 1: Write failing form tests**

Create `users/tests_registration_flow.py` with this initial content:

```python
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from organizations.models import Invitation, Membership, Organization
from users.forms import UserRegistrationForm


User = get_user_model()


@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class UserRegistrationFormTests(TestCase):
    def create_invitation(self, email="invitee@example.test"):
        owner = User.objects.create_user(
            email="owner@example.test",
            password="StrongPassword123!",
        )
        organization = Organization.objects.create(
            name="Invited Org",
            created_by=owner,
        )
        Membership.objects.create(
            organization=organization,
            user=owner,
            role="owner",
        )
        return Invitation.objects.create(
            organization=organization,
            email=email,
            inviter=owner,
            role="member",
        )

    def test_bootstrap_form_marks_saved_user_as_staff(self):
        form = UserRegistrationForm(
            data={
                "email": "first@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
            registration_mode="bootstrap",
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertEqual(user.email, "first@example.test")
        self.assertTrue(user.is_staff)
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_superuser)

    def test_public_form_saves_normal_non_staff_user(self):
        form = UserRegistrationForm(
            data={
                "email": "normal@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
            registration_mode="public",
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertEqual(user.email, "normal@example.test")
        self.assertFalse(user.is_staff)
        self.assertTrue(user.is_active)

    def test_invitation_form_uses_invitation_email_not_posted_email(self):
        invitation = self.create_invitation(email="invitee@example.test")
        form = UserRegistrationForm(
            data={
                "email": "attacker@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
            registration_mode="invitation",
            invitation=invitation,
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertEqual(user.email, "invitee@example.test")
        self.assertFalse(user.is_staff)
```

- [ ] **Step 2: Run form tests to verify they fail**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow.UserRegistrationFormTests -v 2
```

Expected: FAIL with `TypeError` for unexpected `registration_mode` or with assertions showing users are not marked as intended.

- [ ] **Step 3: Update `UserRegistrationForm`**

Replace the existing `UserRegistrationForm` class in `users/forms.py` with:

```python
class UserRegistrationForm(UserCreationForm):
    """Form for user registration."""

    class Meta:
        model = User
        fields = ("email", "password1", "password2")

    def __init__(self, *args, registration_mode="public", invitation=None, **kwargs):
        self.registration_mode = registration_mode
        self.invitation = invitation
        super().__init__(*args, **kwargs)

        if self.invitation:
            self.fields["email"].initial = self.invitation.email
            self.fields["email"].disabled = True
            self.fields["email"].help_text = "This email comes from your invitation."

        for field in self.fields.values():
            field.widget.attrs["class"] = "form-control"

    def clean_email(self):
        if self.invitation:
            return self.invitation.email.lower()

        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with that email already exists.")
        return email

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.invitation:
            user.email = self.invitation.email.lower()
        if self.registration_mode == "bootstrap":
            user.is_staff = True
            user.is_active = True
        if commit:
            user.save()
        return user
```

- [ ] **Step 4: Run form tests**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow.UserRegistrationFormTests -v 2
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add users/forms.py users/tests_registration_flow.py
git commit -m "feat: support bootstrap and invitation registration forms"
```

## Task 4: Enforce Registration Policy In The Register View

**Files:**
- Modify: `users/views.py`
- Modify: `users/tests_registration_flow.py`

- [ ] **Step 1: Add failing register view tests**

Append these imports to the top of `users/tests_registration_flow.py`:

```python
from django.urls import reverse
```

Append this test class to `users/tests_registration_flow.py`:

```python
@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class RegisterViewPolicyTests(TestCase):
    def create_existing_user(self, email="existing@example.test"):
        return User.objects.create_user(
            email=email,
            password="StrongPassword123!",
        )

    def test_get_register_renders_bootstrap_when_no_users_exist(self):
        response = self.client.get(reverse("register"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create first admin")
        self.assertContains(response, "Initialize this Catalyst Networks instance")

    def test_post_register_bootstraps_first_staff_user(self):
        response = self.client.post(
            reverse("register"),
            {
                "email": "first@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertRedirects(response, reverse("dashboard:dashboard"))
        user = User.objects.get(email="first@example.test")
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_get_register_is_closed_after_user_exists(self):
        self.create_existing_user()

        response = self.client.get(reverse("register"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Registration is invitation-only")
        self.assertNotContains(response, "Create account", html=False)

    def test_post_register_is_blocked_after_user_exists(self):
        self.create_existing_user()

        response = self.client.post(
            reverse("register"),
            {
                "email": "second@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email="second@example.test").exists())
        self.assertContains(response, "Registration is invitation-only")

    @override_settings(ALLOW_PUBLIC_REGISTRATION=True)
    def test_public_registration_setting_allows_normal_signup_after_user_exists(self):
        self.create_existing_user()

        response = self.client.post(
            reverse("register"),
            {
                "email": "public@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertRedirects(response, reverse("dashboard:dashboard"))
        user = User.objects.get(email="public@example.test")
        self.assertFalse(user.is_staff)

    @override_settings(ALLOW_BOOTSTRAP_REGISTRATION=False)
    def test_bootstrap_disabled_closes_registration_when_no_users_exist(self):
        response = self.client.get(reverse("register"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Registration is invitation-only")
```

- [ ] **Step 2: Run register view tests to verify they fail**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow.RegisterViewPolicyTests -v 2
```

Expected: FAIL because `register_view` still always renders and processes the generic form.

- [ ] **Step 3: Update `users/views.py` imports**

In `users/views.py`, add these imports:

```python
from django.db import transaction
from .registration_policy import get_registration_state, public_signup_link_available
```

- [ ] **Step 4: Replace `register_view`**

Replace the existing `register_view` function in `users/views.py` with:

```python
def register_view(request):
    """Handle user registration via web UI."""
    if request.user.is_authenticated:
        return redirect("dashboard:dashboard")

    invitation_token = request.GET.get("invitation") or request.POST.get("invitation")
    registration_state = get_registration_state(invitation_token=invitation_token)

    if not registration_state.can_register:
        return render(
            request,
            "base/register.html",
            {
                "form": None,
                "registration_state": registration_state,
                "invitation_token": "",
            },
        )

    if request.method == "POST":
        form = UserRegistrationForm(
            request.POST,
            registration_mode=registration_state.mode,
            invitation=registration_state.invitation,
        )
        if form.is_valid():
            try:
                with transaction.atomic():
                    if registration_state.mode == "bootstrap" and User.objects.exists():
                        messages.error(request, "Registration is no longer available.")
                        return render(
                            request,
                            "base/register.html",
                            {
                                "form": None,
                                "registration_state": get_registration_state(),
                                "invitation_token": "",
                            },
                        )

                    user = form.save()

                    membership = None
                    if registration_state.mode == "invitation":
                        membership = registration_state.invitation.accept(user)
                        if membership is None:
                            raise ValueError("Invitation could not be accepted.")

                login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                if membership:
                    messages.success(
                        request,
                        f"Welcome to {membership.organization.name}! Your account has been created.",
                    )
                    return redirect(
                        "organizations:detail",
                        slug=membership.organization.slug,
                    )

                messages.success(request, "Account created successfully!")
                return redirect("dashboard:dashboard")
            except ValueError:
                messages.error(request, "This invitation is no longer valid.")
    else:
        form = UserRegistrationForm(
            registration_mode=registration_state.mode,
            invitation=registration_state.invitation,
        )

    return render(
        request,
        "base/register.html",
        {
            "form": form,
            "registration_state": registration_state,
            "invitation_token": invitation_token or "",
        },
    )
```

- [ ] **Step 5: Pass registration prompt state to login**

In `login_view`, replace the final render line:

```python
return render(request, 'base/login.html', {'form': form})
```

with:

```python
return render(
    request,
    "base/login.html",
    {
        "form": form,
        "public_signup_link_available": public_signup_link_available(),
    },
)
```

- [ ] **Step 6: Run register view tests**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow.RegisterViewPolicyTests -v 2
```

Expected: FAIL with missing bootstrap, invitation-only, or registration prompt copy because the templates do not render `registration_state` yet. Continue to Task 5 before committing.

## Task 5: Update Auth Templates And Login Prompt Tests

**Files:**
- Modify: `templates/base/register.html`
- Modify: `templates/base/login.html`
- Modify: `users/tests_registration_flow.py`
- Test: `users/tests.py`

- [ ] **Step 1: Add failing login prompt tests**

Append this class to `users/tests_registration_flow.py`:

```python
@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class LoginRegistrationPromptTests(TestCase):
    def test_login_shows_create_link_before_bootstrap(self):
        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create one")
        self.assertContains(response, reverse("register"))

    def test_login_hides_create_link_after_bootstrap(self):
        User.objects.create_user(
            email="existing@example.test",
            password="StrongPassword123!",
        )

        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Create one")
        self.assertContains(response, "Ask an organization owner for an invitation.")
```

- [ ] **Step 2: Run auth flow tests to verify template failures**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow users.tests -v 2
```

Expected: FAIL until the templates use `registration_state` and login prompt context. `users.tests.PublicAuthPageTests.test_login_page_renders_registration_sso_and_versioned_auth_shell` may also need an override because registration is no longer always public.

- [ ] **Step 3: Replace `templates/base/register.html`**

Replace the whole file with:

```django
{% extends "base/auth_base.html" %}

{% block title %}{{ registration_state.title }} - {{ project_meta.NAME }}{% endblock %}

{% block content %}
    <div class="max-w-md mx-auto py-8">
        <div class="ui-form-section">
            <div class="text-center mb-8">
                <h1 class="ui-page-title text-3xl">{{ registration_state.title }}</h1>
                <p class="ui-page-subtitle max-w-none mt-3">{{ registration_state.subtitle }}</p>
            </div>

            {% if registration_state.mode == "closed" %}
                <div class="catalyst-alert catalyst-alert-info">
                    <div class="catalyst-alert-content">
                        <p>Account creation is only available by organization invitation.</p>
                    </div>
                </div>
                <p class="mt-6 text-center text-sm text-gray-500">
                    Already have an account?
                    <a href="{% url 'login' %}" class="font-medium text-primary-400 hover:text-primary-500">Sign in</a>
                </p>
            {% else %}
                {% if registration_state.mode == "invitation" %}
                    <div class="catalyst-alert catalyst-alert-info mb-5">
                        <div class="catalyst-alert-content">
                            <p>You were invited to join {{ registration_state.invitation.organization.name }} as {{ registration_state.invitation.get_role_display }}.</p>
                        </div>
                    </div>
                {% endif %}

                <form method="POST" action="{% url 'register' %}" class="space-y-5">
                    {% csrf_token %}
                    {% if invitation_token %}
                        <input type="hidden" name="invitation" value="{{ invitation_token }}">
                    {% endif %}

                    {% if form.non_field_errors %}
                        <div class="catalyst-alert catalyst-alert-error">
                            <div class="catalyst-alert-content">
                                {% for error in form.non_field_errors %}
                                    <p>{{ error }}</p>
                                {% endfor %}
                            </div>
                        </div>
                    {% endif %}

                    <div>
                        <label for="id_email" class="catalyst-label">Email</label>
                        <input type="email"
                               name="email"
                               id="id_email"
                               required
                               class="catalyst-input"
                               placeholder="you@example.com"
                               value="{{ form.email.value|default_if_none:'' }}"
                               {% if registration_state.mode == "invitation" %}readonly{% endif %}>
                        {% if form.email.errors %}
                            <div class="form-error">
                                {% for error in form.email.errors %}
                                    <p>{{ error }}</p>
                                {% endfor %}
                            </div>
                        {% endif %}
                        {% if registration_state.mode == "invitation" %}
                            <p class="form-help-text">This email comes from your invitation.</p>
                        {% else %}
                            <p class="form-help-text">We will use this email for sign-in and invitations.</p>
                        {% endif %}
                    </div>

                    <div>
                        <label for="id_password1" class="catalyst-label">Password</label>
                        <input type="password" name="password1" id="id_password1" required class="catalyst-input" placeholder="Create a strong password">
                        {% if form.password1.errors %}
                            <div class="form-error">
                                {% for error in form.password1.errors %}
                                    <p>{{ error }}</p>
                                {% endfor %}
                            </div>
                        {% endif %}
                        <div class="mt-3 rounded-xl border border-[var(--ui-border)] bg-[var(--ui-surface-muted)] p-4">
                            <p class="text-xs font-semibold uppercase tracking-[0.08em] text-gray-500 mb-2">Password requirements</p>
                            <ul class="space-y-2 text-sm text-gray-500">
                                <li>At least 8 characters</li>
                                <li>Not commonly used</li>
                                <li>Not entirely numeric</li>
                            </ul>
                        </div>
                    </div>

                    <div>
                        <label for="id_password2" class="catalyst-label">Confirm password</label>
                        <input type="password" name="password2" id="id_password2" required class="catalyst-input" placeholder="Enter password again">
                        {% if form.password2.errors %}
                            <div class="form-error">
                                {% for error in form.password2.errors %}
                                    <p>{{ error }}</p>
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>

                    <button type="submit" class="btn-catalyst btn-catalyst-gradient w-full">
                        {{ registration_state.submit_label }}
                    </button>
                </form>

                <p class="mt-6 text-center text-sm text-gray-500">
                    Already have an account?
                    <a href="{% url 'login' %}" class="font-medium text-primary-400 hover:text-primary-500">Sign in</a>
                </p>
            {% endif %}
        </div>
    </div>
{% endblock %}
```

- [ ] **Step 4: Update `templates/base/login.html` signup prompt**

Replace this block:

```django
        <p class="mt-6 text-center text-sm text-gray-500">
            Don&apos;t have an account?
            <a href="{% url 'register' %}" class="font-medium text-primary-400 hover:text-primary-500">Create one</a>
        </p>
```

with:

```django
        {% if public_signup_link_available %}
        <p class="mt-6 text-center text-sm text-gray-500">
            Don&apos;t have an account?
            <a href="{% url 'register' %}" class="font-medium text-primary-400 hover:text-primary-500">Create one</a>
        </p>
        {% else %}
        <p class="mt-6 text-center text-sm text-gray-500">
            Need access? Ask an organization owner for an invitation.
        </p>
        {% endif %}
```

- [ ] **Step 5: Update existing public auth page test expectations**

In `users/tests.py`, import `override_settings`:

```python
from django.test import TestCase, override_settings
```

Add this decorator above `test_login_page_renders_registration_sso_and_versioned_auth_shell`:

```python
    @override_settings(ALLOW_PUBLIC_REGISTRATION=True)
```

Keep that existing test's `Create one` assertion because this override preserves public signup for the test.

- [ ] **Step 6: Run auth flow tests**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow users.tests -v 2
```

Expected: PASS for form, register view, login prompt, and existing auth shell tests.

- [ ] **Step 7: Commit**

```bash
git add users/views.py templates/base/register.html templates/base/login.html users/tests_registration_flow.py users/tests.py
git commit -m "feat: enforce bootstrap registration policy"
```

## Task 6: Route Anonymous Invitations To Registration Or Login

**Files:**
- Modify: `organizations/views.py`
- Create: `organizations/tests_invitation_registration.py`
- Test: `users/tests_registration_flow.py`

- [ ] **Step 1: Write failing invitation routing tests**

Create `organizations/tests_invitation_registration.py` with:

```python
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from organizations.models import Invitation, Membership, Organization


User = get_user_model()


@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class InvitationRegistrationRoutingTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.test",
            password="StrongPassword123!",
        )
        self.organization = Organization.objects.create(
            name="Routing Org",
            created_by=self.owner,
        )
        Membership.objects.create(
            organization=self.organization,
            user=self.owner,
            role="owner",
        )

    def create_invitation(self, email="invitee@example.test"):
        return Invitation.objects.create(
            organization=self.organization,
            email=email,
            inviter=self.owner,
            role="member",
        )

    def test_anonymous_valid_invitation_for_new_email_redirects_to_registration(self):
        invitation = self.create_invitation()
        accept_url = reverse(
            "organizations:invitation_accept",
            kwargs={"token": invitation.token},
        )
        expected_url = f"{reverse('register')}?{urlencode({'invitation': invitation.token})}"

        response = self.client.get(accept_url)

        self.assertRedirects(response, expected_url, fetch_redirect_response=False)

    def test_anonymous_valid_invitation_for_existing_email_redirects_to_login(self):
        invitation = self.create_invitation(email="existing@example.test")
        User.objects.create_user(
            email="existing@example.test",
            password="StrongPassword123!",
        )
        accept_url = reverse(
            "organizations:invitation_accept",
            kwargs={"token": invitation.token},
        )
        expected_url = f"{reverse('login')}?{urlencode({'next': accept_url})}"

        response = self.client.get(accept_url)

        self.assertRedirects(response, expected_url, fetch_redirect_response=False)

    def test_authenticated_matching_user_accepts_invitation(self):
        invitation = self.create_invitation(email="member@example.test")
        user = User.objects.create_user(
            email="member@example.test",
            password="StrongPassword123!",
        )
        self.client.force_login(user)

        response = self.client.get(
            reverse(
                "organizations:invitation_accept",
                kwargs={"token": invitation.token},
            )
        )

        self.assertRedirects(
            response,
            reverse("organizations:detail", kwargs={"slug": self.organization.slug}),
        )
        self.assertTrue(
            Membership.objects.filter(
                organization=self.organization,
                user=user,
                role="member",
            ).exists()
        )

    def test_authenticated_different_email_cannot_accept_invitation(self):
        invitation = self.create_invitation(email="invitee@example.test")
        user = User.objects.create_user(
            email="other@example.test",
            password="StrongPassword123!",
        )
        self.client.force_login(user)

        response = self.client.get(
            reverse(
                "organizations:invitation_accept",
                kwargs={"token": invitation.token},
            )
        )

        self.assertRedirects(response, reverse("organizations:list"))
        self.assertFalse(
            Membership.objects.filter(
                organization=self.organization,
                user=user,
            ).exists()
        )
```

- [ ] **Step 2: Run invitation routing tests to verify they fail**

Run:

```bash
docker compose exec web python manage.py test organizations.tests_invitation_registration -v 2
```

Expected: FAIL because `invitation_accept` is currently protected by `@login_required`.

- [ ] **Step 3: Update organization view imports**

In `organizations/views.py`, add:

```python
from urllib.parse import urlencode
```

The file already imports `reverse` and `get_user_model`; keep those imports.

- [ ] **Step 4: Remove login requirement from invitation accept**

Remove the `@login_required` decorator immediately above `def invitation_accept(request, token):`.

- [ ] **Step 5: Add anonymous routing to `invitation_accept`**

Inside `invitation_accept`, immediately after:

```python
invitation = get_object_or_404(Invitation, token=token)
```

add:

```python
    if not request.user.is_authenticated:
        if not invitation.is_valid:
            messages.error(request, "This invitation is no longer valid.")
            return redirect("login")

        invited_user_exists = get_user_model().objects.filter(
            email__iexact=invitation.email
        ).exists()
        if invited_user_exists:
            accept_path = reverse(
                "organizations:invitation_accept",
                kwargs={"token": invitation.token},
            )
            return redirect(f"{reverse('login')}?{urlencode({'next': accept_path})}")

        return redirect(f"{reverse('register')}?{urlencode({'invitation': invitation.token})}")
```

Leave the existing authenticated email-match and acceptance logic in place after this block.

- [ ] **Step 6: Run invitation routing tests**

Run:

```bash
docker compose exec web python manage.py test organizations.tests_invitation_registration -v 2
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add organizations/views.py organizations/tests_invitation_registration.py
git commit -m "feat: route invited users through gated registration"
```

## Task 7: Test And Harden Invite-Gated Account Creation

**Files:**
- Modify: `users/tests_registration_flow.py`
- Modify: `users/views.py`

- [ ] **Step 1: Add invite-gated registration integration tests**

Append this class to `users/tests_registration_flow.py`:

```python
@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class InvitationRegistrationViewTests(TestCase):
    def create_invitation(self, email="invitee@example.test", role="member"):
        owner = User.objects.create_user(
            email="owner@example.test",
            password="StrongPassword123!",
        )
        organization = Organization.objects.create(
            name="Invitation Flow Org",
            created_by=owner,
        )
        Membership.objects.create(
            organization=organization,
            user=owner,
            role="owner",
        )
        invitation = Invitation.objects.create(
            organization=organization,
            email=email,
            inviter=owner,
            role=role,
        )
        return invitation, organization

    def test_get_invitation_registration_locks_invited_email(self):
        invitation, organization = self.create_invitation()

        response = self.client.get(
            reverse("register"),
            {"invitation": invitation.token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Accept invitation")
        self.assertContains(response, organization.name)
        self.assertContains(response, 'value="invitee@example.test"')
        self.assertContains(response, "readonly")

    def test_post_invitation_registration_creates_user_and_membership(self):
        invitation, organization = self.create_invitation(email="invitee@example.test")

        response = self.client.post(
            reverse("register"),
            {
                "invitation": invitation.token,
                "email": "attacker@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertRedirects(
            response,
            reverse("organizations:detail", kwargs={"slug": organization.slug}),
        )
        user = User.objects.get(email="invitee@example.test")
        self.assertFalse(User.objects.filter(email="attacker@example.test").exists())
        self.assertTrue(
            Membership.objects.filter(
                organization=organization,
                user=user,
                role="member",
            ).exists()
        )
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, "accepted")
        self.assertIsNotNone(invitation.accepted_at)

    def test_unknown_invitation_token_renders_closed_registration(self):
        response = self.client.get(
            reverse("register"),
            {"invitation": "missing-token"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Registration is invitation-only")

    def test_revoked_invitation_token_does_not_create_user(self):
        invitation, _organization = self.create_invitation(email="invitee@example.test")
        invitation.status = "revoked"
        invitation.revoked_at = timezone.now()
        invitation.save(update_fields=["status", "revoked_at"])

        response = self.client.post(
            reverse("register"),
            {
                "invitation": invitation.token,
                "email": "invitee@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email="invitee@example.test").exists())
        self.assertContains(response, "Registration is invitation-only")
```

Also add this import at the top of `users/tests_registration_flow.py` if it is not already present:

```python
from django.utils import timezone
```

- [ ] **Step 2: Run invite registration tests**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow.InvitationRegistrationViewTests -v 2
```

Expected: PASS.

- [ ] **Step 3: Add duplicate invited-user guard in `register_view`**

In `register_view`, before `user = form.save()`, add this block inside the transaction:

```python
                    if (
                        registration_state.mode == "invitation"
                        and User.objects.filter(
                            email__iexact=registration_state.invitation.email
                        ).exists()
                    ):
                        messages.error(request, "An account already exists for this invitation. Please sign in.")
                        accept_path = reverse(
                            "organizations:invitation_accept",
                            kwargs={"token": registration_state.invitation.token},
                        )
                        return redirect(f"{reverse('login')}?{urlencode({'next': accept_path})}")
```

Add these imports to `users/views.py`:

```python
from urllib.parse import urlencode
```

`reverse` is already imported in `users/views.py`.

- [ ] **Step 4: Add duplicate invited-user test**

Append this method to `InvitationRegistrationViewTests`:

```python
    def test_invitation_registration_redirects_existing_invited_account_to_login(self):
        invitation, _organization = self.create_invitation(email="invitee@example.test")
        User.objects.create_user(
            email="invitee@example.test",
            password="StrongPassword123!",
        )

        response = self.client.post(
            reverse("register"),
            {
                "invitation": invitation.token,
                "email": "invitee@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response["Location"].startswith(reverse("login")))
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, "pending")
```

- [ ] **Step 5: Run invite registration tests again**

Run:

```bash
docker compose exec web python manage.py test users.tests_registration_flow.InvitationRegistrationViewTests -v 2
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add users/views.py users/tests_registration_flow.py
git commit -m "test: cover invite-gated account creation"
```

## Task 8: Document Bootstrap Registration Settings

**Files:**
- Modify: `.env.example`
- Modify: `.env.prod.example`
- Modify: `README.md`
- Modify: `templates/docs/getting_started.html`

- [ ] **Step 1: Update `.env.example`**

After `DJANGO_LOG_FILE=`, add:

```dotenv
# Human Account Registration
# First installer can create the initial admin account at /register/.
# After any user exists, registration is invitation-only unless public registration is enabled.
ALLOW_BOOTSTRAP_REGISTRATION=True
ALLOW_PUBLIC_REGISTRATION=False
```

- [ ] **Step 2: Update `.env.prod.example`**

After `STATIC_ASSET_VERSION=`, add:

```dotenv
# Human Account Registration
# Keep public registration disabled for internet-facing deployments.
ALLOW_BOOTSTRAP_REGISTRATION=True
ALLOW_PUBLIC_REGISTRATION=False
```

- [ ] **Step 3: Update README quick start**

In `README.md`, replace:

```markdown
# Create an admin user
docker compose exec web python manage.py createsuperuser

# Visit the app
open http://localhost:8000
```

with:

```markdown
# Visit the app and create the first admin account
open http://localhost:8000/register/
```

Below that command block, add:

```markdown
The first account can be created from `/register/` on a fresh database. After
that account exists, human registration is invitation-only by default. If you
disable `ALLOW_BOOTSTRAP_REGISTRATION`, create the first admin manually:

```bash
docker compose exec web python manage.py createsuperuser
```
```

- [ ] **Step 4: Update README configuration table**

Add these rows near the other Django settings:

```markdown
| `ALLOW_BOOTSTRAP_REGISTRATION` | Allow `/register/` to create the first admin when no users exist | `True` |
| `ALLOW_PUBLIC_REGISTRATION` | Allow open human account signup after bootstrap; keep `False` for internet-facing installs | `False` |
```

- [ ] **Step 5: Update in-app getting started docs**

In `templates/docs/getting_started.html`, replace the "Initialize the Database" command block:

```html
<pre class="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto text-sm">docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser</pre>
```

with:

```html
<pre class="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto text-sm">docker compose exec web python manage.py migrate</pre>
        <p class="text-sm text-gray-700 mt-2">On a fresh database, visit <code>/register/</code> to create the first admin account. After that first account exists, user registration is invitation-only by default.</p>
        <p class="text-sm text-gray-700 mt-2">If bootstrap registration is disabled, create the first admin from the command line:</p>
        <pre class="bg-gray-50 border border-gray-200 rounded-lg p-4 overflow-x-auto text-sm">docker compose exec web python manage.py createsuperuser</pre>
```

- [ ] **Step 6: Run docs grep checks**

Run:

```bash
grep -RIn "ALLOW_PUBLIC_REGISTRATION\\|ALLOW_BOOTSTRAP_REGISTRATION\\|create the first admin" .env.example .env.prod.example README.md templates/docs/getting_started.html
```

Expected: output includes both env var names in both env examples and README, plus first-admin copy in README and in-app docs.

- [ ] **Step 7: Commit**

```bash
git add .env.example .env.prod.example README.md templates/docs/getting_started.html
git commit -m "docs: explain bootstrap-only registration"
```

## Task 9: Full Regression Verification

**Files:**
- Verify all changed files

- [ ] **Step 1: Run focused tests**

Run:

```bash
docker compose exec web python manage.py test users.tests users.tests_registration_policy users.tests_registration_flow organizations.tests_invitation_registration -v 2
```

Expected: PASS.

- [ ] **Step 2: Run full Django test suite**

Run:

```bash
docker compose exec web python manage.py test -v 2
```

Expected: PASS.

- [ ] **Step 3: Run migration check**

Run:

```bash
docker compose exec web python manage.py makemigrations --check --dry-run
```

Expected: `No changes detected`.

- [ ] **Step 4: Run app health check**

Run:

```bash
docker compose ps
curl -fsS http://localhost:${WEB_PORT:-8000}/health/
```

Expected: Compose services are running and the health endpoint returns success.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git diff --stat HEAD~8..HEAD
git status --short
```

Expected: diff contains only registration, invitation, docs, env example, and test changes. Working tree is clean after the final commit.

- [ ] **Step 6: Final commit if verification required a fix**

If any fix was needed during verification, commit it:

```bash
git add open_cvpn/settings.py users/registration_policy.py users/forms.py users/views.py users/tests.py users/tests_registration_policy.py users/tests_registration_flow.py organizations/views.py organizations/tests_invitation_registration.py templates/base/register.html templates/base/login.html .env.example .env.prod.example README.md templates/docs/getting_started.html
git commit -m "fix: stabilize bootstrap registration flow"
```

Expected: no uncommitted files remain.
