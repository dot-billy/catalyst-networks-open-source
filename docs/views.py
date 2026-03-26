from django.shortcuts import render
from django.contrib.auth.decorators import login_required

@login_required
def node_mgmt_cli(request):
    return render(request, 'docs/node_mgmt_cli.html') 