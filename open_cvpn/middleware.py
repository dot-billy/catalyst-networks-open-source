"""
Custom middleware to handle API error responses.
"""
import ipaddress

from django.conf import settings
from django.http import Http404, JsonResponse
from django.utils.deprecation import MiddlewareMixin
import logging

logger = logging.getLogger(__name__)


class APIErrorMiddleware(MiddlewareMixin):
    """
    Middleware to return JSON error responses for API requests.
    """
    
    def process_response(self, request, response):
        """
        Process the response and convert HTML error pages to JSON for API requests.
        """
        # Only handle API requests
        if not request.path.startswith('/api/'):
            return response
        
        # Only handle error responses
        if response.status_code < 400:
            return response
        
        # Check if response is HTML (error page)
        content_type = response.get('Content-Type', '')
        if 'text/html' in content_type:
            # Convert HTML error page to JSON
            error_data = {
                'error': self.get_error_title(response.status_code),
                'detail': self.get_error_detail(response.status_code, request.path),
                'status_code': response.status_code
            }
            
            return JsonResponse(error_data, status=response.status_code)
        
        return response
    
    def get_error_title(self, status_code):
        """
        Get a human-readable error title based on status code.
        """
        error_titles = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            406: 'Not Acceptable',
            408: 'Request Timeout',
            409: 'Conflict',
            410: 'Gone',
            422: 'Unprocessable Entity',
            429: 'Too Many Requests',
            500: 'Internal Server Error',
            501: 'Not Implemented',
            502: 'Bad Gateway',
            503: 'Service Unavailable',
            504: 'Gateway Timeout',
        }
        return error_titles.get(status_code, 'Error')
    
    def get_error_detail(self, status_code, path):
        """
        Get a detailed error message based on status code and path.
        """
        if status_code == 404:
            return f'The requested resource "{path}" was not found.'
        elif status_code == 403:
            return 'You do not have permission to access this resource.'
        elif status_code == 401:
            return 'Authentication credentials were not provided.'
        elif status_code == 405:
            return 'Method not allowed for this resource.'
        elif status_code == 500:
            return 'An internal server error occurred.'
        else:
            return 'An error occurred while processing your request.'


class AdminIPAllowlistMiddleware:
    """Hide Django admin routes from clients outside the optional allowlist."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        cidrs = settings.ADMIN_IP_ALLOWLIST
        if cidrs and request.path.startswith('/admin/'):
            client_ip = self._client_ip(request)
            networks = [ipaddress.ip_network(cidr, strict=False) for cidr in cidrs]
            if client_ip is None or not any(client_ip in network for network in networks):
                logger.warning("Admin IP allowlist denied client for admin route")
                raise Http404
        return self.get_response(request)

    @staticmethod
    def _client_ip(request):
        hops = settings.ADMIN_TRUSTED_PROXY_HOPS
        forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if hops > 0 and forwarded_for:
            entries = [entry.strip() for entry in forwarded_for.split(',') if entry.strip()]
            candidate = entries[-hops] if len(entries) >= hops else None
        else:
            candidate = request.META.get('REMOTE_ADDR')
        try:
            return ipaddress.ip_address(candidate)
        except (TypeError, ValueError):
            return None
