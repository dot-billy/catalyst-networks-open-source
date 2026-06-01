from allauth.core.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib import messages
from django.shortcuts import redirect

from .models import SSOConfiguration
from .services import (
    SSOLoginIdentity,
    SSOLoginRejected,
    complete_sso_login,
    oidc_provider_id_for_config,
    sync_allauth_app_for_config,
)


SSO_STATE_KEY = 'catalyst_sso'


class CatalystSocialAccountAdapter(DefaultSocialAccountAdapter):
    def generate_state_param(self, state):
        request = getattr(self, 'request', None)
        context = self._session_sso_context(request)
        if context:
            state[SSO_STATE_KEY] = context
        return super().generate_state_param(state)

    def get_app(self, request, provider, client_id=None):
        context = self._request_sso_context(request)
        org_slug = context.get('org_slug')
        if not org_slug:
            self._reject(request, 'Use your organization SSO login to continue.')

        config = self._get_config(org_slug, config_id=context.get('config_id'))
        if not config or not self._provider_matches_config(provider, config):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')
        if not self._app_matches_context(config, context):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')

        app = None
        if config.allauth_app_id:
            from allauth.socialaccount.models import SocialApp

            app = SocialApp.objects.filter(pk=config.allauth_app_id).first()
        if app is None:
            app = sync_allauth_app_for_config(config)
        app.secret = config.get_oidc_client_secret()
        return app

    def pre_social_login(self, request, sociallogin):
        context = self._sociallogin_sso_context(request, sociallogin)
        org_slug = context.get('org_slug')
        if not org_slug:
            self._reject(request, 'Use your organization SSO login to continue.')

        config = self._get_config(org_slug, config_id=context.get('config_id'))
        if not config:
            self._reject(request, 'SSO authentication failed. Contact your administrator.')
        if not self._app_matches_context(config, context):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')

        callback_provider = getattr(sociallogin.account, 'provider', '')
        if callback_provider and not self._provider_matches_config(callback_provider, config):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')

        extra_data = sociallogin.account.extra_data or {}
        if not self._issuer_matches_config(extra_data, config):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')
        if not self._trusted_email_matches_config(extra_data, config):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')

        identity = SSOLoginIdentity(
            email=self._resolve_claim(extra_data, config.oidc_email_claim),
            subject=self._resolve_claim(extra_data, config.oidc_subject_claim),
            provider=self._provider_name(config, sociallogin),
            first_name=self._resolve_claim(extra_data, config.oidc_first_name_claim),
            last_name=self._resolve_claim(extra_data, config.oidc_last_name_claim),
        )

        try:
            user = complete_sso_login(config, identity)
        except SSOLoginRejected:
            self._reject(request, 'SSO authentication failed. Contact your administrator.')

        try:
            self._link_social_account(sociallogin, user)
        except SSOLoginRejected:
            self._reject(request, 'SSO authentication failed. Contact your administrator.')
        request.session.pop('sso_org_slug', None)
        request.session.pop('sso_config_id', None)
        request.session.pop('sso_allauth_app_id', None)
        request.session.pop('sso_next', None)

    def _provider_name(self, config, sociallogin):
        provider = getattr(sociallogin.account, 'provider', '')
        if provider:
            return provider
        if config.oidc_mode == SSOConfiguration.OIDC_GOOGLE:
            return 'google'
        return 'openid_connect'

    def _get_config(self, org_slug, config_id=None):
        queryset = SSOConfiguration.objects.filter(
            organization__slug=org_slug,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
        ).select_related('organization')
        if config_id:
            queryset = queryset.filter(pk=config_id)
        return queryset.first()

    def _request_sso_context(self, request):
        state_context = self._state_sso_context(request)
        if state_context is None and self._request_has_state(request):
            self._reject(request, 'SSO authentication failed. Contact your administrator.')

        session_context = self._session_sso_context(request)
        if state_context:
            if session_context and session_context.get('org_slug') != state_context.get('org_slug'):
                self._reject(request, 'SSO authentication failed. Contact your administrator.')
            return state_context
        return session_context or {}

    def _sociallogin_sso_context(self, request, sociallogin):
        state_context = (getattr(sociallogin, 'state', {}) or {}).get(SSO_STATE_KEY)
        session_context = self._session_sso_context(request)
        if state_context:
            if session_context and session_context.get('org_slug') != state_context.get('org_slug'):
                self._reject(request, 'SSO authentication failed. Contact your administrator.')
            return state_context
        return session_context or {}

    def _session_sso_context(self, request):
        session = getattr(request, 'session', {}) if request is not None else {}
        org_slug = session.get('sso_org_slug')
        config_id = session.get('sso_config_id')
        if not org_slug:
            return {}
        context = {
            'org_slug': org_slug,
        }
        if config_id:
            context['config_id'] = str(config_id)
        app_id = session.get('sso_allauth_app_id')
        if app_id:
            context['app_id'] = str(app_id)
        return context

    def _state_sso_context(self, request):
        state_id = self._request_state_id(request)
        if not state_id:
            return None

        from allauth.socialaccount.internal.statekit import get_states

        state_ts = get_states(request).get(state_id)
        if not state_ts:
            return None
        state, _timestamp = state_ts
        return state.get(SSO_STATE_KEY) or None

    def _request_has_state(self, request):
        return bool(self._request_state_id(request))

    def _request_state_id(self, request):
        if request is None:
            return ''
        query = getattr(request, 'GET', {})
        return query.get('state', '')

    def _app_matches_context(self, config, context):
        expected_app_id = context.get('app_id')
        if not expected_app_id:
            return True
        return str(config.allauth_app_id or '') == str(expected_app_id)

    def _provider_matches_config(self, provider, config):
        provider_id = getattr(provider, 'id', provider)
        provider_id = str(provider_id)
        if config.oidc_mode == SSOConfiguration.OIDC_GOOGLE:
            return provider_id == 'google'

        configured_provider_id = config.oidc_provider_id or oidc_provider_id_for_config(config)
        return provider_id == configured_provider_id

    def _issuer_matches_config(self, extra_data, config):
        if config.oidc_mode != SSOConfiguration.OIDC_GENERIC:
            return True

        expected = self._normalize_issuer(config.oidc_issuer_url)
        actual = self._normalize_issuer(self._resolve_claim(extra_data, 'iss'))
        return bool(expected and actual and expected == actual)

    def _normalize_issuer(self, issuer):
        return (issuer or '').strip().rstrip('/')

    def _trusted_email_matches_config(self, extra_data, config):
        verified = self._resolve_claim(extra_data, 'email_verified')
        if verified not in ('', None) and not self._as_bool(verified):
            return False

        if config.oidc_mode != SSOConfiguration.OIDC_GOOGLE:
            return True

        expected_domain = (config.oidc_allowed_domain or '').strip().lower()
        hosted_domain = (self._resolve_claim(extra_data, 'hd') or '').strip().lower()
        return bool(expected_domain and hosted_domain == expected_domain and self._as_bool(verified))

    def _as_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {'1', 'true', 'yes'}
        return bool(value)

    def _link_social_account(self, sociallogin, user):
        account = sociallogin.account
        provider = getattr(account, 'provider', '')
        uid = getattr(account, 'uid', '')

        if provider and uid:
            from allauth.socialaccount.models import SocialAccount

            existing = SocialAccount.objects.filter(provider=provider, uid=uid).first()
            if existing:
                if existing.user_id != user.id:
                    raise SSOLoginRejected('Social account is linked to another user.')
                existing.extra_data = getattr(account, 'extra_data', {}) or {}
                existing.save(update_fields=['extra_data'])
                sociallogin.account = existing
            elif hasattr(account, 'save'):
                account.user = user
                account.save()
                sociallogin.account = account

        sociallogin.user = user

    def _resolve_claim(self, extra_data, claim):
        for source in (extra_data, extra_data.get('userinfo', {}), extra_data.get('id_token', {})):
            if isinstance(source, dict) and claim in source:
                return source[claim]
        return ''

    def _reject(self, request, message):
        messages.error(request, message)
        raise ImmediateHttpResponse(redirect('login'))
