import os


SMTP_EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
RESEND_EMAIL_BACKEND = "anymail.backends.resend.EmailBackend"
MAILGUN_EMAIL_BACKEND = "django_mailgun.MailgunBackend"


def _env_value(env, name):
    value = env.get(name)
    if value is None:
        return ""
    return str(value).strip()


def build_email_settings(env=None, *, default_from_email):
    """Build Django email settings from environment variables."""
    if env is None:
        env = os.environ

    explicit_backend = _env_value(env, "EMAIL_BACKEND")
    resend_api_key = _env_value(env, "RESEND_API_KEY")
    mailgun_api_key = _env_value(env, "MAILGUN_API_KEY")
    mailgun_domain = _env_value(env, "MAILGUN_DOMAIN")

    config = {
        "EMAIL_BACKEND": SMTP_EMAIL_BACKEND,
        "DEFAULT_FROM_EMAIL": _env_value(env, "DEFAULT_FROM_EMAIL") or default_from_email,
        "RESEND_API_KEY": resend_api_key,
        "MAILGUN_API_KEY": mailgun_api_key,
        "MAILGUN_DOMAIN": mailgun_domain,
    }

    if explicit_backend:
        config["EMAIL_BACKEND"] = explicit_backend
        return config

    if resend_api_key:
        config["EMAIL_BACKEND"] = RESEND_EMAIL_BACKEND
        config["ANYMAIL"] = {"RESEND_API_KEY": resend_api_key}
        return config

    if mailgun_api_key and mailgun_domain:
        config["EMAIL_BACKEND"] = MAILGUN_EMAIL_BACKEND
        config["MAILGUN_ACCESS_KEY"] = mailgun_api_key
        config["MAILGUN_SERVER_NAME"] = mailgun_domain
        return config

    return config
