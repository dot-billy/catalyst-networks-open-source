from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.urls import reverse
from django.conf import settings

def send_invitation_email(invitation):
    """
    Send an invitation email to the invitee.
    """
    context = {
        'organization': invitation.organization,
        'inviter_email': invitation.inviter.email,
        'role': invitation.get_role_display(),
        'accept_url': settings.BASE_URL + reverse(
            'organizations:invitation_accept',
            kwargs={'token': invitation.token}
        ),
        'expiry_days': 7  # This matches the default expiry in the Invitation model
    }
    
    html_message = render_to_string('organizations/emails/invitation.html', context)
    text_message = render_to_string('organizations/emails/invitation.txt', context)
    
    send_mail(
        subject=f"You've been invited to join {invitation.organization.name} on Catalyst Networks",
        message=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[invitation.email],
        html_message=html_message
    )

def send_invitation_accepted_email(invitation):
    """
    Send a notification email to the inviter when the invitation is accepted.
    """
    context = {
        'organization': invitation.organization,
        'invitee_email': invitation.email,
        'role': invitation.get_role_display(),
    }
    
    html_message = render_to_string('organizations/emails/invitation_accepted.html', context)
    text_message = render_to_string('organizations/emails/invitation_accepted.txt', context)
    
    send_mail(
        subject=f"{invitation.email} has joined {invitation.organization.name} on Catalyst Networks",
        message=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[invitation.inviter.email],
        html_message=html_message
    ) 