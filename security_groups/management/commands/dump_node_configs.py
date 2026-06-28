import json
from django.core.management.base import BaseCommand
from nodes.models import Node
from nodes.api_registration import NodeRegistrationView


class Command(BaseCommand):
    help = 'Dump generated Nebula config.yml per node to JSON (config-output equivalence baseline).'

    def add_arguments(self, parser):
        parser.add_argument('out_path')

    def handle(self, *args, **opts):
        builder = NodeRegistrationView()
        out = {}
        for node in Node.objects.all():
            try:
                resp = builder._prepare_node_package(node, 'json')
                out[node.id] = resp.data['config_yaml']
            except Exception as exc:  # certs missing on disk in some envs
                out[node.id] = f'ERROR: {exc}'
        with open(opts['out_path'], 'w') as fh:
            json.dump(out, fh, indent=2, sort_keys=True)
        self.stdout.write(self.style.SUCCESS(f'Wrote {len(out)} node configs to {opts["out_path"]}'))
