import os
from pathlib import Path
from django.core.management.utils import get_random_secret_key


# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


"""
    SECURE CODING [SC-24] Secret Key Management:
    SECRET_KEY is loaded from the environment variable DJANGO_SECRET_KEY.
    If not set (e.g. local development), a new random key is generated at
    startup via get_random_secret_key(). This means the key is never
    hard-coded in source control.
    A leaked SECRET_KEY allows an attacker to forge session cookies, CSRF
    tokens, and any other value Django signs, bypassing all authentication.
    """
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", get_random_secret_key())

"""
    SECURE CODING [SC-25] Debug Mode:
    DEBUG is read from the environment and defaults to True only for local
    development convenience. In production DEBUG must be False; when True,
    Django exposes full stack traces, local variable values, settings dumps,
    and SQL queries directly in the browser to any user who triggers an error.
    """
DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in {"1", "true", "yes", "on"}

"""
    SECURE CODING [SC-26] ALLOWED_HOSTS Restriction:
    Only explicitly listed hostnames are accepted. Requests arriving with any
    other Host header are rejected with a 400 Bad Request, preventing HTTP
    Host header injection attacks that could poison password-reset links or
    cache entries with a malicious hostname.
    """
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]

# Application definition

INSTALLED_APPS = [
    'main',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'crispy_forms',
    'crispy_bootstrap5',
]

MIDDLEWARE = [
        """
        SECURE CODING [SC-30/SC-31] SecurityMiddleware:
        Handles HTTPS redirects, HSTS headers, and several other security
        response headers in one place.  Must be first in the stack so it runs
        before any other middleware can return a response.
        """
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
        """SECURE CODING [SC-27] CSRF Protection:
        CsrfViewMiddleware rejects any POST/PUT/PATCH/DELETE request that does
        not supply a valid, same-origin CSRF token, defending against
        Cross-Site Request Forgery attacks.
        """
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
        """
        SECURE CODING [SC-28] Clickjacking Protection:
        Sets X-Frame-Options: DENY on all responses, preventing the site from
        being embedded in an iframe on a third-party page and used for
        clickjacking attacks.
        """
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'moviereview.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'moviereview.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

"""
SECURE CODING [SC-29] Strong Password Validation:
A single custom validator (StrongPasswordValidator) is registered here,
defined in main/validators.py. It enforces minimum length, at least one
uppercase letter, at least one digit, and at least one special character
in a single class, ensuring all complexity rules are applied together on
every registration and password-change attempt.
This list is enforced by Django on UserCreationForm.save() and any call
to validate_password(), so it cannot be bypassed at the view layer.
"""
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'main.validators.StrongPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "/static/"

STATICFILES_DIRS = [
    BASE_DIR / "main" / "static",
]

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"
CRISPY_TEMPLATE_PACK = "bootstrap5"

"""
SECURE CODING [SC-20] Authentication Redirect URLs:
LOGIN_URL tells @login_required where to send unauthenticated users.
LOGIN_REDIRECT_URL and LOGOUT_REDIRECT_URL define safe landing pages
after authentication events, preventing open-redirect risks from
misconfigured defaults.
"""
LOGIN_URL = 'main:login'
LOGIN_REDIRECT_URL = 'main:home'
LOGOUT_REDIRECT_URL = 'main:home'

"""
SECURE CODING [SC-31] Secure CSRF Cookie:
Same principle as SESSION_COOKIE_SECURE applied to the CSRF cookie.
Transmitting the CSRF token over plain HTTP would allow it to be captured
and replayed by a network attacker, undermining CSRF protection.
"""
CSRF_COOKIE_SECURE = not DEBUG

"""
SECURE CODING [SC-30] Secure Session Cookie:
SESSION_COOKIE_SECURE=True instructs the browser to only transmit the
session cookie over HTTPS, preventing it from being intercepted over a
plain HTTP connection (e.g. on a public Wi-Fi network).
Tied to DEBUG so it is automatically enabled in any non-debug environment.
"""
SESSION_COOKIE_SECURE = not DEBUG

"""
SECURE CODING [SC-32] HTTPS Enforcement (SSL Redirect):
SECURE_SSL_REDIRECT=True causes SecurityMiddleware to issue a permanent
301 redirect from any HTTP request to its HTTPS equivalent, ensuring all
traffic is encrypted in transit.  Configurable via environment variable
so it can be disabled when a reverse proxy (e.g. nginx) handles TLS.
"""
SECURE_SSL_REDIRECT = os.environ.get("DJANGO_SECURE_SSL_REDIRECT", str(not DEBUG)).lower() in {
    "1",
    "true",
    "yes",
    "on",
}

"""
SECURE CODING [SC-33] HTTP Strict Transport Security (HSTS):
Once a browser has visited the site over HTTPS, HSTS instructs it to
refuse any future plain-HTTP connections for SECURE_HSTS_SECONDS seconds
(default 1 year in production), eliminating SSL-stripping attack vectors.
SECURE_HSTS_INCLUDE_SUBDOMAINS extends this to all subdomains.
SECURE_HSTS_PRELOAD allows the domain to be submitted to browser preload
lists, providing protection even on the very first visit.
All three are disabled in DEBUG mode to avoid locking out local HTTP dev.
"""
SECURE_HSTS_SECONDS = int(os.environ.get("DJANGO_SECURE_HSTS_SECONDS", "31536000" if not DEBUG else "0"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
