"""SAML2 helper functions using python3-saml."""

from django.conf import settings
from django.urls import reverse
from onelogin.saml2.auth import OneLogin_Saml2_Auth


def prepare_django_request(request):
    """Convert a Django HttpRequest into the format python3-saml expects."""
    return {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': request.META.get('SERVER_PORT', '443' if request.is_secure() else '80'),
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
    }


def get_sp_urls(sso_config):
    """Return canonical Service Provider URLs for an organization's SAML routes."""
    base_url = settings.BASE_URL.rstrip('/')
    slug = sso_config.organization.slug
    return {
        'metadata': f'{base_url}{reverse("sso:metadata", kwargs={"slug": slug})}',
        'acs': f'{base_url}{reverse("sso:acs", kwargs={"slug": slug})}',
        'login': f'{base_url}{reverse("sso:login", kwargs={"slug": slug})}',
    }


def get_saml_settings(sso_config, request):
    """Build python3-saml settings dict from an SSOConfiguration model instance."""
    sp_urls = get_sp_urls(sso_config)
    idp_settings = {
        'entityId': sso_config.idp_entity_id,
        'singleSignOnService': {
            'url': sso_config.idp_sso_url,
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        },
        'x509cert': sso_config.idp_x509_cert,
    }
    if sso_config.idp_slo_url:
        idp_settings['singleLogoutService'] = {
            'url': sso_config.idp_slo_url,
            'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        }

    return {
        'strict': True,
        'debug': settings.DEBUG,
        'sp': {
            'entityId': sp_urls['metadata'],
            'assertionConsumerService': {
                'url': sp_urls['acs'],
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            },
            'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        },
        'idp': idp_settings,
        'security': {
            'nameIdEncrypted': False,
            'authnRequestsSigned': False,
            'logoutRequestSigned': False,
            'logoutResponseSigned': False,
            'signMetadata': False,
            'wantMessagesSigned': True,
            'wantAssertionsSigned': True,
            'wantNameIdEncrypted': False,
            'requestedAuthnContext': False,
        },
    }


def init_saml_auth(request, sso_config):
    """Initialize a OneLogin_Saml2_Auth instance."""
    req = prepare_django_request(request)
    saml_settings = get_saml_settings(sso_config, request)
    return OneLogin_Saml2_Auth(req, saml_settings)
