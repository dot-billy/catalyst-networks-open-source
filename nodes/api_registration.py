import io
import ipaddress
import logging
import os
import random
import secrets
import subprocess
import tempfile
import zipfile

from django.conf import settings
from django.core.cache import cache
from django.core.files import File
from django.db import transaction
from django.http import FileResponse, HttpResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from drf_spectacular.utils import OpenApiExample, extend_schema
from rest_framework import serializers, status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from certificates.models import CertificateAuthority
from open_cvpn.response_schemas import ERROR_RESPONSES, SUCCESS_EXAMPLES
from organizations.models import NetworkRange, Organization

from .models import Node, NodeRegistrationToken
from .serializers import AuthenticatedNodeRegistrationSerializer

logger = logging.getLogger(__name__)
AUTH_SCHEME = 'Bearer'

class NodeRegistrationSerializer(serializers.Serializer):
    organization_slug = serializers.CharField(max_length=255)
    node_name = serializers.CharField(max_length=255)
    registration_token = serializers.CharField(max_length=255)
    is_lighthouse = serializers.BooleanField(default=False)
    public_ip = serializers.CharField(max_length=255, required=False)
    fqdn = serializers.CharField(max_length=255, required=False)
    external_port = serializers.IntegerField(required=False)

@method_decorator(csrf_exempt, name='dispatch')
class NodeRegistrationView(APIView):
    """
    API endpoint for secure node registration.
    
    This endpoint allows new nodes to register themselves securely
    and receive their certificates and configuration.
    """
    authentication_classes = []  # Allow both authenticated and unauthenticated requests
    permission_classes = [AllowAny]  # Allow both authenticated and unauthenticated requests
    
    def _check_rate_limit(self, request):
        """
        Check if the request exceeds rate limits for node registration.
        
        Rate limits:
        - 5 registrations per IP per hour
        - 10 registrations per organization per hour
        """
        # Get client IP
        client_ip = self._get_client_ip(request)
        
        # Check IP-based rate limit (5 per hour)
        ip_key = f"node_registration_ip:{client_ip}"
        ip_count = cache.get(ip_key, 0)
        if ip_count >= 5:
            return Response({
                'error': 'Rate Limit Exceeded',
                'detail': f'Too many registration attempts from this IP address. Maximum 5 registrations per hour allowed.',
                'status_code': 429
            }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        # Check organization-based rate limit (10 per hour)
        org_slug = request.data.get('organization_slug')
        if org_slug:
            org_key = f"node_registration_org:{org_slug}"
            org_count = cache.get(org_key, 0)
            if org_count >= 10:
                return Response({
                    'error': 'Rate Limit Exceeded',
                    'detail': f'Too many registration attempts for organization "{org_slug}". Maximum 10 registrations per hour allowed.',
                    'status_code': 429
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)
        
        return None
    
    def _increment_rate_limit(self, request):
        """Increment rate limit counters."""
        client_ip = self._get_client_ip(request)
        org_slug = request.data.get('organization_slug')
        
        # Increment IP counter (expires in 1 hour)
        ip_key = f"node_registration_ip:{client_ip}"
        cache.set(ip_key, cache.get(ip_key, 0) + 1, 3600)
        
        # Increment organization counter (expires in 1 hour)
        if org_slug:
            org_key = f"node_registration_org:{org_slug}"
            cache.set(org_key, cache.get(org_key, 0) + 1, 3600)
    
    def _get_client_ip(self, request):
        """Get the client IP address from the request.

        Only trusts X-Forwarded-For when USE_X_FORWARDED_HOST is enabled,
        indicating the app is behind a trusted reverse proxy.
        """
        from django.conf import settings
        if getattr(settings, 'USE_X_FORWARDED_HOST', False):
            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                # Take the first (client) IP from the chain
                ip = x_forwarded_for.split(',')[0].strip()
                return ip
        return request.META.get('REMOTE_ADDR')
    
    @extend_schema(
        operation_id='register_node',
        summary='Register a new node (Dual Flow Support)',
        description='''
        Register a new node in the organization and receive certificates and configuration.
        
        ## Two Registration Flows Supported:
        
        ### 1. Authenticated Registration (Desktop App Flow)
        - **Authentication**: JWT token in the Authorization header
        - **Use Case**: Desktop applications, user-initiated registrations
        - **Required Fields**: `node_name` only
        - **Organization**: Determined from URL path parameter
        
        ### 2. Token-based Registration (Fleet Deployment Flow)  
        - **Authentication**: Registration token in request body
        - **Use Case**: Automated deployment, CI/CD pipelines, server provisioning
        - **Required Fields**: `organization_slug`, `node_name`, `registration_token`
        - **Organization**: Specified in request body
        
        The endpoint automatically detects which flow to use based on the presence of authentication headers and request body fields.
        ''',
        request={
            'application/json': {
                'oneOf': [
                    {
                        'type': 'object',
                        'title': '🖥️ Desktop App Flow (JWT Authentication)',
                        'description': 'For desktop applications and user-initiated registrations. Requires JWT token in Authorization header.',
                        'properties': {
                            'node_name': {
                                'type': 'string', 
                                'description': 'Name or hostname for the node (alphanumeric, hyphens, underscores, dots allowed)',
                                'example': 'my-laptop',
                                'minLength': 1,
                                'maxLength': 255,
                                'pattern': '^[a-zA-Z0-9._-]+$'
                            },
                            'is_lighthouse': {
                                'type': 'boolean', 
                                'default': False, 
                                'description': 'Whether this node should be a lighthouse (coordination server). Lighthouse nodes help other nodes connect.',
                                'example': False
                            },
                            'public_ip': {
                                'type': 'string', 
                                'format': 'ipv4', 
                                'description': 'Public IP address for lighthouse nodes (REQUIRED if is_lighthouse=true)',
                                'example': '203.0.113.1',
                                'pattern': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                            },
                            'fqdn': {
                                'type': 'string', 
                                'description': 'Fully Qualified Domain Name for lighthouse nodes (alternative to public_ip)',
                                'example': 'lighthouse.example.com',
                                'maxLength': 255,
                                'pattern': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
                            },
                            'external_port': {
                                'type': 'integer', 
                                'minimum': 1, 
                                'maximum': 65535, 
                                'description': 'External port for lighthouse nodes (default: 4242)',
                                'example': 4242,
                                'default': 4242
                            }
                        },
                        'required': ['node_name'],
                        'additionalProperties': False
                    },
                    {
                        'type': 'object',
                        'title': '🚀 Fleet Deployment Flow (Registration Token)',
                        'description': 'For automated deployment, CI/CD pipelines, and server provisioning. Uses registration token for authentication.',
                        'properties': {
                            'organization_slug': {
                                'type': 'string', 
                                'description': 'Slug of the organization to register the node with (lowercase, hyphens only)',
                                'example': 'my-organization',
                                'minLength': 1,
                                'maxLength': 255,
                                'pattern': '^[a-z0-9-]+$'
                            },
                            'node_name': {
                                'type': 'string', 
                                'description': 'Name or hostname for the node (alphanumeric, hyphens, underscores, dots allowed)',
                                'example': 'server-01',
                                'minLength': 1,
                                'maxLength': 255,
                                'pattern': '^[a-zA-Z0-9._-]+$'
                            },
                            'registration_token': {
                                'type': 'string', 
                                'description': 'Registration token for the organization (obtained from organization dashboard)',
                                'example': 'abc123-def456-ghi789',
                                'minLength': 1,
                                'maxLength': 255,
                                'pattern': '^[a-zA-Z0-9_-]+$'
                            },
                            'is_lighthouse': {
                                'type': 'boolean', 
                                'default': False, 
                                'description': 'Whether this node should be a lighthouse (coordination server). Lighthouse nodes help other nodes connect.',
                                'example': False
                            },
                            'public_ip': {
                                'type': 'string', 
                                'format': 'ipv4', 
                                'description': 'Public IP address for lighthouse nodes (REQUIRED if is_lighthouse=true)',
                                'example': '203.0.113.1',
                                'pattern': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
                            },
                            'fqdn': {
                                'type': 'string', 
                                'description': 'Fully Qualified Domain Name for lighthouse nodes (alternative to public_ip)',
                                'example': 'lighthouse.example.com',
                                'maxLength': 255,
                                'pattern': r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
                            },
                            'external_port': {
                                'type': 'integer', 
                                'minimum': 1, 
                                'maximum': 65535, 
                                'description': 'External port for lighthouse nodes (default: 4242)',
                                'example': 4242,
                                'default': 4242
                            }
                        },
                        'required': ['organization_slug', 'node_name', 'registration_token'],
                        'additionalProperties': False
                    }
                ]
            }
        },
        responses={
            200: {
                'description': 'Node successfully registered',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'node_id': {'type': 'integer', 'example': 123},
                                'node_name': {'type': 'string', 'example': 'my-node'},
                                'nebula_ip': {'type': 'string', 'example': '10.0.0.5'},
                                'is_lighthouse': {'type': 'boolean', 'example': False},
                                'api_token': {'type': 'string', 'example': 'generated-api-token'},
                                'certificate': {'type': 'string', 'example': '-----BEGIN CERTIFICATE-----...'},
                                'key': {'type': 'string', 'example': '-----BEGIN NEBULA X25519 PRIVATE KEY-----...'},
                                'ca_certificate': {'type': 'string', 'example': '-----BEGIN CERTIFICATE-----...'},
                                'config_yaml': {'type': 'string', 'example': '# Nebula configuration file...'},
                                'expiration': {'type': 'string', 'format': 'date-time', 'example': '2025-09-11T15:00:00Z'}
                            }
                        }
                    }
                }
            },
            400: ERROR_RESPONSES[400],
            401: ERROR_RESPONSES[401],
            403: ERROR_RESPONSES[403],
            404: ERROR_RESPONSES[404],
            500: ERROR_RESPONSES[500]
        },
        tags=['Node Registration']
    )
    def post(self, request, slug=None, format=None):
        """
        Register a new node and generate its certificates.
        
        Requires a valid registration token for the specified organization.
        Returns the node's certificate, key, and configuration.
        
        The returned configuration can be directly saved as a Nebula config file.
        """
        # Check rate limits
        rate_limit_response = self._check_rate_limit(request)
        if rate_limit_response:
            return rate_limit_response
        
        # Determine registration flow based on authentication and request data
        # Check if user is authenticated by looking for JWT token in Authorization header
        is_authenticated = False
        auth_header = request.headers.get('Authorization', '')
        auth_parts = auth_header.split(None, 1) if auth_header else []
        if len(auth_parts) == 2 and auth_parts[0] == AUTH_SCHEME:
            # Try to authenticate the user with the JWT token
            from rest_framework_simplejwt.authentication import JWTAuthentication
            jwt_auth = JWTAuthentication()
            try:
                user, token = jwt_auth.authenticate(request)
                if user and user.is_authenticated:
                    request.user = user
                    is_authenticated = True
            except:
                pass
        
        has_reg_credential = 'registration_token' in request.data
        
        if is_authenticated and not has_reg_credential:
            # Authenticated flow (desktop app) - no token required
            return self._handle_authenticated_registration(request, slug)
        elif has_reg_credential:
            # Token-based flow (fleet deployment) - token required
            return self._handle_token_registration(request, slug)
        else:
            # Neither authenticated nor token provided
            return Response({
                'error': 'Authentication Required',
                'detail': 'Either authentication credentials or a registration token is required for node registration.',
                'status_code': 401
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    def _handle_authenticated_registration(self, request, slug):
        """Handle authenticated node registration (desktop app flow)."""
        # Use the organization slug from the URL path
        organization_slug = slug
        if not organization_slug:
            return Response({
                'error': 'Organization Required',
                'detail': 'Organization slug must be provided in the URL path.',
                'status_code': 400
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate user has access to the organization
        try:
            organization = Organization.objects.get(slug=organization_slug)
            # Check if user is a member of the organization
            if not request.user.organizations.filter(id=organization.id).exists():
                return Response({
                    'error': 'Access Denied',
                    'detail': f'You do not have access to organization "{organization_slug}".',
                    'status_code': 403
                }, status=status.HTTP_403_FORBIDDEN)
        except Organization.DoesNotExist:
            return Response({
                'error': 'Organization Not Found',
                'detail': f'Organization "{organization_slug}" does not exist.',
                'status_code': 404
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Use authenticated serializer
        serializer = AuthenticatedNodeRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'error': 'Validation Error',
                'detail': serializer.errors,
                'status_code': 400
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract validated data
        node_name = serializer.validated_data['node_name']
        is_lighthouse = serializer.validated_data['is_lighthouse']
        public_ip = serializer.validated_data.get('public_ip')
        fqdn = serializer.validated_data.get('fqdn')
        external_port = serializer.validated_data.get('external_port')
        
        # Create node using authenticated user
        return self._create_node(
            organization=organization,
            node_name=node_name,
            is_lighthouse=is_lighthouse,
            public_ip=public_ip,
            fqdn=fqdn,
            external_port=external_port,
            created_by=request.user,
            token=None  # No token for authenticated flow
        )
    
    def _handle_token_registration(self, request, slug):
        """Handle token-based node registration (fleet deployment flow)."""
        # Use the organization slug from the URL path
        organization_slug = slug
        if not organization_slug:
            return Response({
                'error': 'Organization Required',
                'detail': 'Organization slug must be provided in the URL path.',
                'status_code': 400
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Use token-based serializer
        serializer = NodeRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'error': 'Validation Error',
                'detail': serializer.errors,
                'status_code': 400
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Extract validated data
        token_value = serializer.validated_data['registration_token']
        node_name = serializer.validated_data['node_name']
        is_lighthouse = serializer.validated_data['is_lighthouse']
        public_ip = serializer.validated_data.get('public_ip')
        fqdn = serializer.validated_data.get('fqdn')
        external_port = serializer.validated_data.get('external_port')
        
        # Validate organization and token
        try:
            organization = Organization.objects.get(slug=organization_slug)
        except Organization.DoesNotExist:
            return Response({
                'error': 'Organization Not Found',
                'detail': f'Organization "{organization_slug}" does not exist.',
                'status_code': 404
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Verify token is valid
        try:
            token = NodeRegistrationToken.objects.get(
                organization=organization,
                token=token_value,
                is_active=True
            )
            
            # Check if token is valid
            if not token.is_valid():
                if token.expires_at < timezone.now():
                    return Response({
                        'error': 'Token Expired',
                        'detail': f'Registration token expired on {token.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC")}. Please request a new token.',
                        'status_code': 401
                    }, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    return Response({
                        'error': 'Token Usage Limit Exceeded',
                        'detail': f'Registration token has been used {token.uses_count} times (limit: {token.uses_allowed if token.uses_allowed != -1 else "unlimited"}). Please request a new token.',
                        'status_code': 401
                    }, status=status.HTTP_401_UNAUTHORIZED)
            
        except NodeRegistrationToken.DoesNotExist:
            return Response({
                'error': 'Invalid Registration Token',
                'detail': f'Registration token not found for organization "{organization_slug}". Please check your token or contact your administrator.',
                'status_code': 401
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        # Create node using token
        return self._create_node(
            organization=organization,
            node_name=node_name,
            is_lighthouse=is_lighthouse,
            public_ip=public_ip,
            fqdn=fqdn,
            external_port=external_port,
            created_by=token.created_by if token else None,
            token=token
        )
    
    def _create_node(self, organization, node_name, is_lighthouse, public_ip, fqdn, external_port, created_by, token):
        """Create a node with the given parameters."""
        try:
            # Get the first available CA for the organization
            ca = organization.certificate_authorities.first()
            if not ca:
                return Response({
                    'error': 'Certificate Authority Missing',
                    'detail': f'No certificate authority configured for organization "{organization.slug}". Please contact your administrator to set up a certificate authority.',
                    'status_code': 400
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Prevent regular node registration if no lighthouses exist
            if not is_lighthouse:
                lighthouse_count = Node.objects.filter(organization=organization, is_lighthouse=True).count()
                if lighthouse_count == 0:
                    return Response({
                        'error': 'No Lighthouse Nodes Available',
                        'detail': f'Organization "{organization.slug}" has no lighthouse nodes configured. Please create a lighthouse node first before registering regular nodes.',
                        'status_code': 400
                    }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get available IP address
            next_ip = self._get_next_available_ip(organization)
            if not next_ip:
                return Response({
                    'error': 'No Available IP Addresses',
                    'detail': f'Organization "{organization.slug}" has no available IP addresses in its network range. Please contact your administrator to expand the network range.',
                    'status_code': 400
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create the node in a transaction
            with transaction.atomic():
                try:
                    # Generate a secure API token for the node
                    api_token = secrets.token_urlsafe(32)

                    node = Node(
                        name=node_name,
                        organization=organization,
                        certificate_authority=ca,
                        is_lighthouse=is_lighthouse,
                        nebula_ip=next_ip,
                        created_by=created_by,
                        api_token=api_token,
                        public_ip=public_ip if is_lighthouse else None,
                        fqdn=fqdn if is_lighthouse else None,
                        external_port=external_port if is_lighthouse and external_port is not None else 4242
                    )
                    # Skip validation since we're creating directly
                    # Temporarily patch the save method to skip validation
                    original_save = node.save
                    def skip_validation_save(*args, **kwargs):
                        # Call the parent save method directly, bypassing our custom save
                        super(Node, node).save(*args, **kwargs)
                    node.save = skip_validation_save
                    node.save(force_insert=True)
                    
                    # Refresh the node to get the ID from database
                    node.refresh_from_db()
                    
                    # Mark token as used if it's a real token (not master token)
                    if token:
                        token.use_token()
                        
                except Exception as e:
                    return Response({
                        'error': 'Node Creation Failed',
                        'detail': f'Failed to create node "{node_name}": {str(e)}. Please try again or contact support if the problem persists.',
                        'status_code': 500
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Generate certificate outside transaction
            try:
                self._generate_certificate(node)
            except Exception as e:
                # If certificate generation fails, delete the node
                node.delete()
                return Response({
                    'error': 'Certificate Generation Failed',
                    'detail': f'Failed to generate certificate for node "{node_name}": {str(e)}. Please try again or contact support if the problem persists.',
                    'status_code': 500
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Create response with certificate, key, and config
            # Note: request is not available in this method, so we'll use default format
            response_data = self._prepare_node_package(node, 'json')
            
            # Add the api_token to the response
            if isinstance(response_data, Response):
                response_data.data['api_token'] = node.api_token
            elif hasattr(response_data, 'data'):
                response_data.data['api_token'] = node.api_token
            else:
                # If it's a FileResponse or other, do nothing
                pass
            return response_data
                
        except Exception as e:
            return Response({
                'error': 'Registration Failed',
                'detail': f'An unexpected error occurred during node registration: {str(e)}. Please try again or contact support if the problem persists.',
                'status_code': 500
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    
    def _verify_registration_token(self, organization, token):
        """
        Legacy method - replaced by direct token validation
        """
        return False
    
    def _get_next_available_ip(self, organization):
        """
        Get the next available IP address for a node.
        """
        with transaction.atomic():
            network_ranges = list(NetworkRange.objects.select_for_update().filter(
                organization=organization
            ))
            
            if not network_ranges:
                return None
            
            network_range = network_ranges[0]
            network = ipaddress.ip_network(network_range.cidr)
            
            # Get all used IPs
            used_ips = set(Node.objects.filter(
                organization=organization
            ).values_list('nebula_ip', flat=True))
            
            used_ip_objects = set()
            for ip in used_ips:
                try:
                    # Handle IP strings that might have CIDR notation
                    if ip and '/' in ip:
                        ip = ip.split('/')[0]
                    used_ip_objects.add(ipaddress.ip_address(ip))
                except ValueError:
                    continue
            
            # Find first available
            for ip in network.hosts():
                if ip not in used_ip_objects:
                    return str(ip)
            
            return None
    
    def _generate_certificate(self, node):
        """
        Generate certificate and key for a node.
        """
        ca = node.certificate_authority
        name = node.name
        ip = node.nebula_ip
        
        # Create cert directory in dedicated cert storage
        cert_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'certs', f'org-{node.organization.id}')
        os.makedirs(cert_dir, exist_ok=True)
        
        # Generate certificate paths with UTC datetime suffix for uniqueness
        timestamp_str = timezone.now().strftime("%Y%m%dT%H%M%SZ")
        cert_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.crt')
        key_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.key')
        
        # Prepare command with just the essential parameters
        cmd = [
            'nebula-cert', 'sign',
            '-name', name,
            '-ip', f'{ip}/24',
            '-ca-crt', ca.ca_cert.path,
            '-ca-key', ca.ca_key.path,
            '-out-crt', cert_path,
            '-out-key', key_path
        ]
        
        # Include Nebula groups from org security groups and lighthouse role
        group_names = []
        if node.is_lighthouse:
            group_names.append('lighthouse')
        group_names.extend(list(node.security_groups.values_list('name', flat=True)))
        if group_names:
            cmd.extend(['-groups', ','.join(group_names)])
        
        # REMOVED: We don't add public IP as subnets anymore, it's not essential for certificate
        
        print(f"Generating certificate with command: {' '.join(cmd)}")
        
        # Generate certificate
        subprocess.run(cmd, check=True)
        
        # Save to node
        with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
            node.cert_path.save(f'{name}-{timestamp_str}.crt', File(cert_file), save=False)
            node.key_path.save(f'{name}-{timestamp_str}.key', File(key_file), save=False)
        
        # Get expiration
        result = subprocess.run([
            'nebula-cert', 'print',
            '-path', cert_path
        ], capture_output=True, text=True, check=True)
        
        # Parse expiration from output and convert to Django-compatible format
        for line in result.stdout.split('\n'):
            if 'Not After' in line:
                exp_str = line.split(': ')[1].strip()
                # Convert the date format to Django-compatible format
                try:
                    # Parse the date format: "2025-05-03 11:54:04 +0000 UTC"
                    # Convert to YYYY-MM-DD HH:MM:SS format
                    exp_parts = exp_str.split()
                    if len(exp_parts) >= 3:
                        # Extract date and time, ignore timezone for now
                        date_part = exp_parts[0]
                        time_part = exp_parts[1]
                        node.cert_expiration = f"{date_part}T{time_part}Z"
                    else:
                        # Fallback: use current time + 1 year
                        node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                except Exception as e:
                    print(f"Error parsing certificate expiration: {e}")
                    # Fallback: use current time + 1 year
                    node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                break
        
        node.save()
    
    def _prepare_node_package(self, node, format_type='json'):
        """
        Prepare a package containing the node's certificates and configuration.
        
        Returns either a JSON response or a ZIP file depending on the format parameter.
        """
        print(f"\n==== Preparing package for node {node.id} - {node.name} ====")
        
        # Read certificate and key
        with open(node.cert_path.path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        with open(node.key_path.path, 'rb') as key_file:
            key_data = key_file.read()
        
        # Get CA certificate
        with open(node.certificate_authority.ca_cert.path, 'rb') as ca_file:
            ca_data = ca_file.read()
        
        # Generate a basic config
        lighthouse_nodes = []
        for lighthouse in Node.objects.filter(organization=node.organization, is_lighthouse=True):
            if lighthouse.id != node.id:  # Don't include self if this is a lighthouse
                lighthouse_nodes.append({
                    'name': lighthouse.name,
                    'ip': lighthouse.nebula_ip,
                    'public_ip': lighthouse.public_ip,
                    'fqdn': lighthouse.fqdn,
                    'external_port': lighthouse.external_port or 4242
                })
        
        config = {
            'pki': {
                # Inline the actual CA, cert, and key contents
                'ca': ca_data.decode('utf-8'),
                'cert': cert_data.decode('utf-8'),
                'key': key_data.decode('utf-8'),
            },
            'static_host_map': {},
            'lighthouse': {
                'am_lighthouse': node.is_lighthouse,
                'interval': 60
            },
            'listen': {
                'host': '0.0.0.0',
                'port': node.external_port if node.is_lighthouse else 4242
            },
            'punchy': {
                'punch': True
            },
            'relay': {
                'am_relay': False,
                'use_relays': True
            },
            'tun': {
                'disabled': False,
                'dev': 'nebula1',
                'drop_local_broadcast': False,
                'drop_multicast': False,
                'tx_queue': 500,
                'mtu': 1300
            },
            'logging': {
                'level': 'info',
                'format': 'text'
            },
            'firewall': {
                'conntrack': {
                    'tcp_timeout': '12m',
                    'udp_timeout': '3m',
                    'default_timeout': '10m',
                    'max_connections': 100000
                },
                'outbound': [
                    # Default outbound rules to allow all outgoing traffic
                    {'port': 'any', 'proto': 'any', 'host': 'any'}
                ],
                'inbound': [
                    # Allow all ICMP traffic by default
                    {'proto': 'icmp', 'host': 'any', 'port': '0'}
                    # Note: We've removed the default allow-all rule here and will only include it if no specific rules exist
                ]
            }
        }
        
        # Add lighthouses to config
        if lighthouse_nodes:
            # For non-lighthouse nodes, add the lighthouse hosts list
            if not node.is_lighthouse:
                config['lighthouse']['hosts'] = [lh['ip'] for lh in lighthouse_nodes]
            
            # Build the static_host_map with proper host mapping
            for lh in lighthouse_nodes:
                if lh['fqdn'] and lh['external_port']:
                    # If FQDN is available, use it
                    config['static_host_map'][lh['ip']] = [f"{lh['fqdn']}:{lh['external_port']}"]
                elif lh['public_ip'] and lh['external_port']:
                    # Otherwise use public IP if available
                    config['static_host_map'][lh['ip']] = [f"{lh['public_ip']}:{lh['external_port']}"]
                else:
                    # Fallback: use the nebula IP as the endpoint (for testing/development)
                    # In production, lighthouse nodes should have public_ip or fqdn set
                    config['static_host_map'][lh['ip']] = [f"{lh['ip']}:{lh['external_port']}"]
        
        # Add security group rules
        # Get all security groups this node belongs to
        print(f"Getting firewall rules for node {node.id} - {node.name}")
        all_firewall_rules = node.get_all_applicable_firewall_rules()
        print(f"Node has {all_firewall_rules.count()} applicable firewall rules")

        # Only add the default allow-all rule if there are no explicit rules defined
        if not all_firewall_rules.exists():
            print(f"No firewall rules applicable to node {node.name}, including default allow-all rule")
            # Add default allow-all rule only if no specific rules exist
            config['firewall']['inbound'].append({'port': 'any', 'proto': 'any', 'host': 'any'})
        else:
            print(f"Adding {all_firewall_rules.count()} firewall rules for node {node.name}")
            # Process all applicable rules
            for rule in all_firewall_rules:
                firewall_rule = {}
                
                # Protocol/port
                if rule.protocol == 'any':
                    firewall_rule['proto'] = 'any'
                    firewall_rule['port'] = 'any'
                elif rule.protocol == 'icmp':
                    firewall_rule['proto'] = 'icmp'
                else:  # TCP or UDP
                    firewall_rule['proto'] = rule.protocol
                    if rule.port_min is not None and rule.port_max is not None:
                        if rule.port_min == rule.port_max:
                            firewall_rule['port'] = rule.port_min
                        else:
                            firewall_rule['port'] = f"{rule.port_min}-{rule.port_max}"
                    else:
                        firewall_rule['port'] = 'any'
                
                # Source handling - prioritize in this order:
                # 1. Source Groups (if any)
                # 2. Source Nodes (if any)
                # 3. Source CIDR (if any)
                # 4. Skip rule if no source is specified (avoid empty host field)
                
                # Check if rule has source groups
                group_names = list(rule.source_groups.values_list('name', flat=True))
                if group_names:
                    # Use the 'groups' field when source groups are specified
                    firewall_rule['groups'] = group_names
                    # Do NOT add an empty 'host' field when groups are specified
                else:
                    # Only handle host field if no source groups were specified
                    node_ips = list(rule.source_nodes.values_list('nebula_ip', flat=True))
                    if node_ips:
                        firewall_rule['host'] = node_ips if len(node_ips) > 1 else node_ips[0]
                    # Source CIDR
                    elif rule.source_cidr:
                        firewall_rule['host'] = rule.source_cidr
                    else:
                        # If no source is specified, skip this rule
                        print(f"  Skipping rule with no source specified: {rule}")
                        continue
                
                # Add the rule to the config
                rule_source = "node direct" if rule.node else f"security group: {rule.security_group.name}"
                print(f"  Adding firewall rule from {rule_source}: {firewall_rule}")
                config['firewall']['inbound'].append(firewall_rule)
        
        # Let's also verify what's in the database directly
        print(f"Database check: Node {node.id} security groups:")
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM nodes_node_security_groups WHERE node_id = %s", [node.id])
            assignments = cursor.fetchall()
            print(f"Raw security group assignments: {assignments}")
            
        # Format as YAML string
        config_yaml = self._dict_to_yaml(config)
        
        if format_type == 'zip':
            # Create ZIP file
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as zip_file:
                zip_file.writestr('ca.crt', ca_data)
                zip_file.writestr('host.crt', cert_data)
                zip_file.writestr('host.key', key_data)
                zip_file.writestr('config.yml', config_yaml.encode('utf-8'))
            
            buffer.seek(0)
            response = FileResponse(
                buffer,
                as_attachment=True,
                filename=f'nebula-{node.name}-{node.nebula_ip}.zip'
            )
            return response
        else:
            # Return JSON
            return Response({
                'node_id': node.id,
                'node_name': node.name,
                'nebula_ip': node.nebula_ip,
                'is_lighthouse': node.is_lighthouse,
                'certificate': cert_data.decode('utf-8'),
                'key': key_data.decode('utf-8'),
                'ca_certificate': ca_data.decode('utf-8'),
                'config_yaml': config_yaml,
                'expiration': node.cert_expiration,
            })
    
    def _dict_to_yaml(self, d, indent=0):
        """
        Convert a dictionary to YAML format with proper formatting for certificates.
        """
        yaml = ""
        for key, value in d.items():
            yaml += ' ' * indent + str(key) + ':'
            if isinstance(value, dict):
                yaml += '\n' + self._dict_to_yaml(value, indent + 2)
            elif isinstance(value, list):
                yaml += '\n'
                for item in value:
                    if isinstance(item, dict):
                        yaml += ' ' * (indent + 2) + '-\n' + self._dict_to_yaml(item, indent + 4)
                    else:
                        yaml += ' ' * (indent + 2) + '- ' + str(item) + '\n'
            elif isinstance(value, str) and ('\n' in value or '-----BEGIN' in value):
                # Format certificate data with pipe character
                yaml += ' |\n'
                for line in value.splitlines():
                    yaml += ' ' * (indent + 2) + line + '\n'
            else:
                yaml += ' ' + str(value) + '\n'
        return yaml
