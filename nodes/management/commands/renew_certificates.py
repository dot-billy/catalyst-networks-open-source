import sys
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta
from nodes.models import Node
from nodes.tasks import renew_node_certificate, renew_expiring_certificates
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Renew certificates for nodes that are expiring soon or specific nodes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--node-id',
            type=int,
            help='ID of a specific node to renew certificate for'
        )
        
        parser.add_argument(
            '--organization-id',
            type=int,
            help='Renew certificates for all nodes in this organization'
        )
        
        parser.add_argument(
            '--days',
            type=int,
            default=14,
            help='Renew certificates expiring within this many days (default: 14)'
        )
        
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force certificate renewal even if not expiring soon'
        )
        
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Only show which certificates would be renewed without actually renewing them'
        )

    def handle(self, *args, **options):
        node_id = options.get('node_id')
        organization_id = options.get('organization_id')
        days = options.get('days')
        force = options.get('force')
        dry_run = options.get('dry_run')
        
        # Specific node renewal
        if node_id:
            try:
                node = Node.objects.get(id=node_id)
                
                if not force and node.cert_expiration and node.cert_expiration > timezone.now() + timedelta(days=days):
                    self.stdout.write(self.style.WARNING(
                        f"Node {node.name} (ID: {node.id}) certificate is not expiring within {days} days. "
                        f"Use --force to renew anyway."
                    ))
                    return
                
                if dry_run:
                    self.stdout.write(self.style.SUCCESS(
                        f"Would renew certificate for node {node.name} (ID: {node.id})"
                    ))
                    return
                
                self.stdout.write(f"Renewing certificate for node {node.name} (ID: {node.id})...")
                result = renew_node_certificate(node.id)
                
                if result['success']:
                    self.stdout.write(self.style.SUCCESS(
                        f"Successfully renewed certificate for node {node.name}. "
                        f"Old expiration: {result.get('old_expiration')}. "
                        f"New expiration: {result.get('new_expiration')}."
                    ))
                else:
                    raise CommandError(f"Failed to renew certificate: {result.get('error')}")
                
            except Node.DoesNotExist:
                raise CommandError(f"Node with ID {node_id} does not exist")
            
            return
        
        # Organization-specific renewal
        if organization_id:
            query = Node.objects.filter(organization_id=organization_id)
            
            if not force:
                expiry_cutoff = timezone.now() + timedelta(days=days)
                query = query.filter(cert_expiration__lt=expiry_cutoff)
            
            nodes = list(query)
            
            if not nodes:
                self.stdout.write(self.style.WARNING(
                    f"No nodes found in organization {organization_id} with certificates expiring within {days} days."
                ))
                return
            
            self.stdout.write(f"Found {len(nodes)} nodes in organization {organization_id} to renew certificates for.")
            
            if dry_run:
                for node in nodes:
                    self.stdout.write(f"  - Would renew: {node.name} (ID: {node.id}), expires: {node.cert_expiration}")
                return
            
            success_count = 0
            for node in nodes:
                try:
                    self.stdout.write(f"  - Renewing: {node.name} (ID: {node.id})...")
                    result = renew_node_certificate(node.id)
                    
                    if result['success']:
                        success_count += 1
                        self.stdout.write(self.style.SUCCESS(
                            f"    ✓ Successfully renewed. New expiration: {result.get('new_expiration')}"
                        ))
                    else:
                        self.stdout.write(self.style.ERROR(
                            f"    ✗ Failed: {result.get('error')}"
                        ))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"    ✗ Error: {str(e)}"))
            
            self.stdout.write(self.style.SUCCESS(
                f"Completed renewal process for organization {organization_id}. "
                f"Successfully renewed {success_count} of {len(nodes)} certificates."
            ))
            
            return
        
        # Bulk renewal of expiring certificates
        self.stdout.write(f"Checking for certificates expiring within {days} days...")
        
        expiry_cutoff = timezone.now() + timedelta(days=days)
        expiring_nodes = Node.objects.filter(cert_expiration__lt=expiry_cutoff)
        
        if force:
            expiring_nodes = Node.objects.all()
            self.stdout.write(self.style.WARNING("Force option enabled - will renew ALL certificates!"))
        
        if not expiring_nodes.exists():
            self.stdout.write(self.style.SUCCESS("No certificates found that need renewal."))
            return
        
        self.stdout.write(f"Found {expiring_nodes.count()} certificates that need renewal.")
        
        if dry_run:
            for node in expiring_nodes:
                days_until_expiry = (node.cert_expiration - timezone.now()).days if node.cert_expiration else 0
                self.stdout.write(f"  - Would renew: {node.name} (ID: {node.id}), expires in {days_until_expiry} days")
            return
        
        self.stdout.write("Starting bulk certificate renewal...")
        result = renew_expiring_certificates()
        
        self.stdout.write(self.style.SUCCESS(
            f"Completed bulk certificate renewal. "
            f"Successfully renewed: {result['succeeded']} certificates. "
            f"Failed: {result['failed']} certificates."
        ))
        
        if result['failed'] > 0:
            failed_nodes = [n for n in result['nodes'] if not n['success']]
            self.stdout.write(self.style.WARNING("Failures:"))
            for node in failed_nodes:
                self.stdout.write(self.style.ERROR(
                    f"  - Node {node['node_name']} (ID: {node['node_id']}): {node.get('error')}"
                ))
        
        return 