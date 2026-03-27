from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required
def node_mgmt_cli(request):
    return render(request, 'docs/node_mgmt_cli.html')


@login_required
def getting_started(request):
    return render(request, 'docs/getting_started.html')


@login_required
def network_setup(request):
    return render(request, 'docs/network_setup.html')


@login_required
def certificate_management(request):
    return render(request, 'docs/certificate_management.html')


@login_required
def api_reference(request):
    return render(request, 'docs/api_reference.html')


@login_required
def security_policies(request):
    return render(request, 'docs/security_policies.html')


@login_required
def bulk_operations(request):
    return render(request, 'docs/bulk_operations.html')


@login_required
def troubleshooting(request):
    return render(request, 'docs/troubleshooting.html')
