"""
Custom response schemas for API documentation.
These provide clear examples of what API responses look like.
"""
from rest_framework import status


# Common error response schemas
ERROR_RESPONSES = {
    400: {
        'description': 'Bad Request',
        'content': {
            'application/json': {
                'examples': {
                    'validation_error': {
                        'summary': 'Validation Error',
                        'value': {
                            'error': 'Bad Request',
                            'detail': {
                                'field_name': ['This field is required.'],
                                'email': ['Enter a valid email address.']
                            },
                            'status_code': 400
                        }
                    }
                }
            }
        }
    },
    401: {
        'description': 'Unauthorized',
        'content': {
            'application/json': {
                'examples': {
                    'unauthorized': {
                        'summary': 'Authentication Required',
                        'value': {
                            'error': 'Unauthorized',
                            'detail': 'Authentication credentials were not provided.',
                            'status_code': 401
                        }
                    }
                }
            }
        }
    },
    403: {
        'description': 'Forbidden',
        'content': {
            'application/json': {
                'examples': {
                    'forbidden': {
                        'summary': 'Access Denied',
                        'value': {
                            'error': 'Forbidden',
                            'detail': 'You do not have permission to perform this action.',
                            'status_code': 403
                        }
                    }
                }
            }
        }
    },
    404: {
        'description': 'Not Found',
        'content': {
            'application/json': {
                'examples': {
                    'not_found': {
                        'summary': 'Resource Not Found',
                        'value': {
                            'error': 'Not Found',
                            'detail': 'The requested resource was not found.',
                            'status_code': 404
                        }
                    }
                }
            }
        }
    },
    405: {
        'description': 'Method Not Allowed',
        'content': {
            'application/json': {
                'examples': {
                    'method_not_allowed': {
                        'summary': 'Method Not Allowed',
                        'value': {
                            'error': 'Method Not Allowed',
                            'detail': 'Method "PUT" not allowed.',
                            'status_code': 405
                        }
                    }
                }
            }
        }
    },
    500: {
        'description': 'Internal Server Error',
        'content': {
            'application/json': {
                'examples': {
                    'server_error': {
                        'summary': 'Server Error',
                        'value': {
                            'error': 'Internal Server Error',
                            'detail': 'An unexpected server error occurred.',
                            'status_code': 500
                        }
                    }
                }
            }
        }
    }
}

# Success response examples (as dictionaries for YAML serialization)
SUCCESS_EXAMPLES = {
    'token_response': {
        'summary': 'JWT Token Response',
        'description': 'Successful authentication returns access and refresh tokens',
        'value': {
            'access': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
            'refresh': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...',
            'user': {
                'id': 1,
                'email': 'user@example.com',
                'first_name': 'John',
                'last_name': 'Doe',
                'date_joined': '2024-01-15T10:30:00Z'
            }
        }
    },
    'organization_list': {
        'summary': 'List of Organizations',
        'description': 'Paginated list of organizations the user has access to',
        'value': {
            'count': 2,
            'next': None,
            'previous': None,
            'results': [
                {
                    'id': 1,
                    'name': 'Acme Corp',
                    'slug': 'acme-corp',
                    'created_at': '2024-01-15T10:30:00Z',
                    'created_by': {
                        'id': 1,
                        'email': 'admin@acme.com'
                    },
                    'members_count': 5,
                    'user_role': 'admin'
                },
                {
                    'id': 2,
                    'name': 'Tech Startup',
                    'slug': 'tech-startup',
                    'created_at': '2024-02-01T14:20:00Z',
                    'created_by': {
                        'id': 2,
                        'email': 'founder@techstartup.com'
                    },
                    'members_count': 3,
                    'user_role': 'member'
                }
            ]
        }
    },
    'node_list': {
        'summary': 'List of Nodes',
        'description': 'Paginated list of nodes in the organization',
        'value': {
            'count': 3,
            'next': None,
            'previous': None,
            'results': [
                {
                    'id': 1,
                    'name': 'web-server-01',
                    'hostname': 'web1.example.com',
                    'nebula_ip': '10.0.0.1',
                    'external_port': 4242,
                    'fqdn': 'web1.example.com',
                    'is_lighthouse': False,
                    'is_active': True,
                    'last_checkin': '2024-01-15T10:30:00Z',
                    'created_at': '2024-01-15T10:30:00Z'
                },
                {
                    'id': 2,
                    'name': 'database-server',
                    'hostname': 'db1.example.com',
                    'nebula_ip': '10.0.0.2',
                    'external_port': 4243,
                    'fqdn': 'db1.example.com',
                    'is_lighthouse': False,
                    'is_active': True,
                    'last_checkin': '2024-01-15T09:45:00Z',
                    'created_at': '2024-01-15T09:45:00Z'
                }
            ]
        }
    },
    'member_list': {
        'summary': 'List of Members',
        'description': 'List of members in the organization',
        'value': {
            'count': 3,
            'next': None,
            'previous': None,
            'results': [
                {
                    'id': 1,
                    'user': {
                        'id': 1,
                        'email': 'admin@example.com'
                    },
                    'organization': {
                        'id': 1,
                        'name': 'Acme Corp',
                        'slug': 'acme-corp',
                        'created_at': '2024-01-15T10:30:00Z',
                        'created_by': {
                            'id': 1,
                            'email': 'admin@example.com'
                        },
                        'members_count': 3,
                        'user_role': 'admin'
                    },
                    'role': 'admin',
                    'created_at': '2024-01-15T10:30:00Z'
                },
                {
                    'id': 2,
                    'user': {
                        'id': 2,
                        'email': 'user@example.com'
                    },
                    'organization': {
                        'id': 1,
                        'name': 'Acme Corp',
                        'slug': 'acme-corp',
                        'created_at': '2024-01-15T10:30:00Z',
                        'created_by': {
                            'id': 1,
                            'email': 'admin@example.com'
                        },
                        'members_count': 3,
                        'user_role': 'member'
                    },
                    'role': 'member',
                    'created_at': '2024-01-16T14:20:00Z'
                }
            ]
        }
    }
}
