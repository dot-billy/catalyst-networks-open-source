import logging
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from onelogin.saml2.errors import OneLogin_Saml2_Error

from organizations.models import Membership, Organization

from .forms import SSOConfigurationForm
from .models import SSOConfiguration
from .saml import get_sp_urls, init_saml_auth
from .services import (
    SSOLoginIdentity,
    SSOLoginRejected,
    complete_sso_login,
    oidc_provider_id_for_config,
    sync_allauth_app_for_config,
)

logger = logging.getLogger(__name__)


def sso_login(request, slug):
    """Initiate SSO login for an organization."""
    org = get_object_or_404(Organization, slug=slug)
    sso_config = getattr(org, 'sso_config', None)

    if not sso_config or not sso_config.is_enabled:
        messages.error(request, 'SSO is not enabled for this organization.')
        return redirect('login')

    if sso_config.is_oidc:
        return oidc_login(request, slug, config=sso_config)

    return saml_login(request, slug, config=sso_config)


def saml_login(request, slug, config=None):
    """Initiate SAML SSO login for an organization."""
    if config is None:
        org = get_object_or_404(Organization, slug=slug)
        config = getattr(org, 'sso_config', None)

    sso_config = config
    if not sso_config or not sso_config.is_enabled:
        messages.error(request, 'SSO is not enabled for this organization.')
        return redirect('login')

    auth = init_saml_auth(request, sso_config)
    return_to = _safe_return_url(request.GET.get('next'), request)
    if return_to:
        return redirect(auth.login(return_to=return_to))
    return redirect(auth.login())


def oidc_login(request, slug, config=None):
    """Seed Catalyst org SSO context and delegate OAuth/OIDC to allauth."""
    if config is None:
        org = get_object_or_404(Organization, slug=slug)
        config = getattr(org, 'sso_config', None)
    else:
        org = config.organization

    if not config or not config.is_enabled or not config.is_oidc:
        messages.error(request, 'OIDC SSO is not enabled for this organization.')
        return redirect('login')

    app = sync_allauth_app_for_config(config)
    request.session['sso_org_slug'] = org.slug
    request.session['sso_config_id'] = config.pk
    request.session['sso_allauth_app_id'] = app.pk
    safe_next = _safe_return_url(request.GET.get('next'), request)
    if safe_next:
        request.session['sso_next'] = safe_next
    else:
        request.session.pop('sso_next', None)

    params = [('process', 'login')]
    if safe_next:
        params.append(('next', safe_next))

    if config.oidc_mode == SSOConfiguration.OIDC_GOOGLE:
        login_url = reverse('google_login')
    else:
        login_url = reverse('openid_connect_login', kwargs={'provider_id': config.oidc_provider_id})
    return redirect(f'{login_url}?{urlencode(params)}')


@csrf_exempt
def sso_acs(request, slug):
    """SAML Assertion Consumer Service — receives IdP response after login."""
    if request.method != 'POST':
        return HttpResponseBadRequest('ACS endpoint requires POST')

    org = get_object_or_404(Organization, slug=slug)
    sso_config = getattr(org, 'sso_config', None)

    if not sso_config or not sso_config.is_enabled:
        messages.error(request, 'SSO is not enabled for this organization.')
        return redirect('login')

    auth = init_saml_auth(request, sso_config)
    try:
        auth.process_response()
    except OneLogin_Saml2_Error as exc:
        logger.error('SAML ACS exception for org %s: %s', org.slug, exc)
        messages.error(request, 'SSO authentication failed. Please try again or contact your administrator.')
        return redirect('login')

    errors = auth.get_errors()

    if errors:
        logger.error('SAML ACS errors for org %s: %s (reason: %s)',
                      org.slug, errors, auth.get_last_error_reason())
        messages.error(request, 'SSO authentication failed. Please try again or contact your administrator.')
        return redirect('login')

    if not auth.is_authenticated():
        messages.error(request, 'SSO authentication was not successful.')
        return redirect('login')

    # Extract attributes from SAML response
    attributes = auth.get_attributes()
    name_id = auth.get_nameid()

    email = _get_attribute(attributes, sso_config.attribute_email, name_id)
    if not email:
        messages.error(request, 'No email address received from identity provider.')
        return redirect('login')

    first_name = _get_attribute(attributes, sso_config.attribute_first_name, '')
    last_name = _get_attribute(attributes, sso_config.attribute_last_name, '')
    identity = SSOLoginIdentity(
        email=email,
        subject=name_id or email,
        provider=SSOConfiguration.PROVIDER_SAML,
        first_name=first_name or '',
        last_name=last_name or '',
    )

    try:
        user = complete_sso_login(sso_config, identity)
    except SSOLoginRejected as exc:
        logger.info('Rejected SSO login for org %s via %s: %s', org.slug, identity.provider, exc)
        if str(exc) == 'User account is inactive.':
            messages.error(request, 'Your account has been deactivated.')
        elif str(exc) == 'No account found for this email.':
            messages.error(request, 'No account found for this email. Contact your administrator.')
        else:
            messages.error(request, 'SSO authentication failed. Contact your administrator.')
        return redirect('login')

    # Log the user in (specify backend to avoid ambiguity with axes)
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    logger.info('SSO login successful for %s via org %s', user.email, org.slug)

    return_to = _safe_return_url(request.POST.get('RelayState'), request)
    return redirect(return_to or settings.LOGIN_REDIRECT_URL)


def sso_metadata(request, slug):
    """Serve SP metadata XML for the organization's SAML config."""
    org = get_object_or_404(Organization, slug=slug)
    sso_config = getattr(org, 'sso_config', None)

    if not sso_config:
        return HttpResponseBadRequest('SSO is not configured for this organization.')

    auth = init_saml_auth(request, sso_config)
    metadata = auth.get_settings().get_sp_metadata()
    errors = auth.get_settings().validate_metadata(metadata)

    if errors:
        return HttpResponseBadRequest(', '.join(errors))

    return HttpResponse(metadata, content_type='text/xml')


@login_required
def sso_configure(request, slug):
    """Configure SSO settings for an organization (owner/admin only)."""
    org = get_object_or_404(Organization, slug=slug)

    # Check that user is owner or admin
    membership = Membership.objects.filter(
        user=request.user, organization=org, role__in=['owner', 'admin']
    ).first()
    if not membership:
        messages.error(request, 'You must be an organization owner or admin to configure SSO.')
        return redirect('organizations:detail', slug=slug)

    sso_config, _created = SSOConfiguration.objects.get_or_create(
        organization=org,
        defaults={
            'idp_entity_id': '',
            'idp_sso_url': 'https://example.com',
            'idp_x509_cert': '',
            'is_enabled': False,
        },
    )

    if request.method == 'POST':
        form = SSOConfigurationForm(request.POST, instance=sso_config)
        if form.is_valid():
            config = form.save()
            if config.is_oidc:
                sync_allauth_app_for_config(config)
            messages.success(request, 'SSO configuration saved successfully.')
            return redirect('sso:configure', slug=slug)
    else:
        form = SSOConfigurationForm(instance=sso_config)

    sp_urls = get_sp_urls(sso_config)
    oidc_callback_provider_id = sso_config.oidc_provider_id or oidc_provider_id_for_config(sso_config)
    oidc_initiation_path = reverse('sso:oidc_login', kwargs={'slug': org.slug})

    return render(request, 'sso/configure.html', {
        'organization': org,
        'form': form,
        'sso_config': sso_config,
        'sp_metadata_url': sp_urls['metadata'],
        'sp_acs_url': sp_urls['acs'],
        'sp_login_url': sp_urls['login'],
        'oidc_callback_provider_id': oidc_callback_provider_id,
        'google_callback_url': request.build_absolute_uri('/accounts/google/login/callback/'),
        'generic_oidc_callback_url': request.build_absolute_uri(
            f'/accounts/oidc/{oidc_callback_provider_id}/login/callback/'
        ),
        'oidc_initiation_url': request.build_absolute_uri(oidc_initiation_path),
        'membership': membership,
    })


@login_required
@require_POST
def sso_toggle(request, slug):
    """Enable or disable SSO for an organization."""
    org = get_object_or_404(Organization, slug=slug)

    membership = Membership.objects.filter(
        user=request.user, organization=org, role__in=['owner', 'admin']
    ).first()
    if not membership:
        messages.error(request, 'You must be an organization owner or admin to manage SSO.')
        return redirect('organizations:detail', slug=slug)

    sso_config = getattr(org, 'sso_config', None)
    if not sso_config:
        messages.error(request, 'SSO has not been configured yet.')
        return redirect('sso:configure', slug=slug)

    # Validate that required fields are populated before enabling
    if not sso_config.is_enabled:
        if sso_config.is_saml and (
            not sso_config.idp_entity_id or not sso_config.idp_sso_url or not sso_config.idp_x509_cert
        ):
            messages.error(request, 'Cannot enable SSO: IdP Entity ID, SSO URL, and X.509 certificate are required.')
            return redirect('sso:configure', slug=slug)
        if sso_config.is_oidc:
            if not sso_config.oidc_mode or not sso_config.oidc_client_id or not sso_config.oidc_client_secret_encrypted:
                messages.error(request, 'Cannot enable SSO: OIDC mode, client ID, and client secret are required.')
                return redirect('sso:configure', slug=slug)
            if sso_config.oidc_mode == SSOConfiguration.OIDC_GOOGLE and not sso_config.oidc_allowed_domain:
                messages.error(request, 'Cannot enable SSO: Google Workspace SSO requires an allowed email domain.')
                return redirect('sso:configure', slug=slug)
            if sso_config.oidc_mode == SSOConfiguration.OIDC_GENERIC and not sso_config.oidc_issuer_url:
                messages.error(request, 'Cannot enable SSO: Issuer URL is required for generic OIDC.')
                return redirect('sso:configure', slug=slug)
            sync_allauth_app_for_config(sso_config)
        sso_config.is_enabled = True
        messages.success(request, 'SSO has been enabled.')
    else:
        sso_config.is_enabled = False
        sso_config.enforce_sso = False
        messages.success(request, 'SSO has been disabled.')

    sso_config.save()
    return redirect('sso:configure', slug=slug)


def _get_attribute(attributes, attr_name, fallback=''):
    """Safely extract a SAML attribute value."""
    if not attr_name:
        return fallback
    values = attributes.get(attr_name, [])
    if values and isinstance(values, list):
        return values[0]
    return fallback


def _safe_return_url(url, request):
    if url and url_has_allowed_host_and_scheme(
        url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return url
    return ''
