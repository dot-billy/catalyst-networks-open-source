"""
Custom error handlers for API endpoints to return JSON responses instead of HTML.
"""
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView


def api_404_handler(request, exception=None):
    """
    Custom 404 handler that returns JSON for API requests.
    """
    # Check if this is an API request
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Not Found',
            'detail': 'The requested resource was not found.',
            'status_code': 404
        }, status=404)
    
    # For non-API requests, render our custom 404 template
    return render(request, '404.html', status=404)


def api_500_handler(request, exception=None):
    """
    Custom 500 handler that returns JSON for API requests.
    """
    # Check if this is an API request
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Internal Server Error',
            'detail': 'An internal server error occurred.',
            'status_code': 500
        }, status=500)
    
    # For non-API requests, render our custom 500 template
    return render(request, '500.html', status=500)


def api_403_handler(request, exception=None):
    """
    Custom 403 handler that returns JSON for API requests.
    """
    # Check if this is an API request
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Forbidden',
            'detail': 'You do not have permission to access this resource.',
            'status_code': 403
        }, status=403)
    
    # For non-API requests, render our custom 403 template
    return render(request, '403.html', status=403)


def api_400_handler(request, exception=None):
    """
    Custom 400 handler that returns JSON for API requests.
    """
    # Check if this is an API request
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Bad Request',
            'detail': 'The request was invalid or cannot be served.',
            'status_code': 400
        }, status=400)
    
    # For non-API requests, render our custom 400 template
    return render(request, '400.html', status=400)


def api_502_handler(request, exception=None):
    """
    Custom 502 handler that returns JSON for API requests.
    """
    # Check if this is an API request
    if request.path.startswith('/api/'):
        return JsonResponse({
            'error': 'Bad Gateway',
            'detail': 'The service is temporarily unavailable.',
            'status_code': 502
        }, status=502)
    
    # For non-API requests, render our custom 502 template
    return render(request, '502.html', status=502)
