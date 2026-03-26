from django.apps import AppConfig


class NodesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'nodes'
    
    def ready(self):
        # Import OpenAPI extensions to register them
        from . import openapi_extensions