"""
Custom exception handlers for Django REST Framework to return consistent JSON error responses.
"""
from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status
from django.http import Http404
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError
import logging

logger = logging.getLogger(__name__)


def custom_exception_handler(exc, context):
    """
    Custom exception handler that returns consistent JSON error responses.
    """
    # Get the standard error response
    response = exception_handler(exc, context)
    
    if response is not None:
        # Customize the error response format
        custom_response_data = {
            'error': get_error_title(response.status_code),
            'detail': response.data.get('detail', 'An error occurred'),
            'status_code': response.status_code
        }
        
        # Add additional details for specific error types
        if isinstance(exc, Http404):
            custom_response_data['detail'] = 'The requested resource was not found.'
        elif isinstance(exc, PermissionDenied):
            custom_response_data['detail'] = 'You do not have permission to access this resource.'
        elif isinstance(exc, DatabaseError):
            custom_response_data['detail'] = 'A database error occurred.'
            logger.error(f"Database error: {exc}", exc_info=True)
        
        # Handle validation errors
        if response.status_code == status.HTTP_400_BAD_REQUEST:
            if 'non_field_errors' in response.data:
                custom_response_data['detail'] = response.data['non_field_errors'][0]
            elif len(response.data) == 1:
                # Single field error
                field, errors = next(iter(response.data.items()))
                custom_response_data['detail'] = f"{field}: {errors[0] if isinstance(errors, list) else errors}"
                custom_response_data['field'] = field
        
        response.data = custom_response_data
    
    return response


def get_error_title(status_code):
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
