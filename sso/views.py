import logging

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from onelogin.saml2.errors import OneLogin_Saml2_Error

from organizations.models import Membership, Organization

from .forms import SSOConfigurationForm
from .models import SSOConfiguration
from .saml import get_sp_urls, init_saml_auth

logger = logging.getLogger(__name__)
User = get_user_model()


def sso_login(request, slug):
    """Initiate SAML SSO login for an organization."""
    org = get_object_or_404(Organization, slug=slug)
    sso_config = getattr(org, 'sso_config', None)

    if not sso_config or not sso_config.is_enabled:
        messages.error(request, 'SSO is not enabled for this organization.')
        return redirect('login')

    auth = init_saml_auth(request, sso_config)
    return_to = _safe_return_url(request.GET.get('next'), request)
    if return_to:
        return redirect(auth.login(return_to=return_to))
    return redirect(auth.login())


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

    email = email.lower().strip()
    first_name = _get_attribute(attributes, sso_config.attribute_first_name, '')
    last_name = _get_attribute(attributes, sso_config.attribute_last_name, '')

    # Find or create the user
    user = User.objects.filter(email=email).first()
    created_user = False

    if user is None:
        if not sso_config.auto_create_users:
            messages.error(request, 'No account found for this email. Contact your administrator.')
            return redirect('login')

        user = User.objects.create_user(
            email=email,
            first_name=first_name or '',
            last_name=last_name or '',
        )
        user.set_unusable_password()
        user.save(update_fields=['password'])
        created_user = True
        logger.info('Auto-provisioned user %s via SSO for org %s', email, org.slug)
    elif not Membership.objects.filter(user=user, organization=org).exists():
        logger.info('Rejected SSO login for existing non-member %s via org %s', email, org.slug)
        messages.error(request, 'SSO authentication failed. Contact your administrator.')
        return redirect('login')

    # Update name if provided and user doesn't have one
    if first_name and not user.first_name:
        user.first_name = first_name
    if last_name and not user.last_name:
        user.last_name = last_name
    if not user.is_active:
        messages.error(request, 'Your account has been deactivated.')
        return redirect('login')
    user.save()

    if created_user:
        Membership.objects.create(
            user=user,
            organization=org,
            role=sso_config.default_role,
        )

    # Log the user in (specify backend to avoid ambiguity with axes)
    login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    logger.info('SSO login successful for %s via org %s', email, org.slug)

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
            form.save()
            messages.success(request, 'SSO configuration saved successfully.')
            return redirect('sso:configure', slug=slug)
    else:
        form = SSOConfigurationForm(instance=sso_config)

    sp_urls = get_sp_urls(sso_config)

    return render(request, 'sso/configure.html', {
        'organization': org,
        'form': form,
        'sso_config': sso_config,
        'sp_metadata_url': sp_urls['metadata'],
        'sp_acs_url': sp_urls['acs'],
        'sp_login_url': sp_urls['login'],
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
        if not sso_config.idp_entity_id or not sso_config.idp_sso_url or not sso_config.idp_x509_cert:
            messages.error(request, 'Cannot enable SSO: IdP Entity ID, SSO URL, and X.509 certificate are required.')
            return redirect('sso:configure', slug=slug)
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
