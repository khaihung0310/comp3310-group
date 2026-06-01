from urllib.parse import urlparse

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import *

#movie add form


def _reject_control_characters(value):
    if value and any(ord(character) < 32 and character not in "\r\n\t" for character in value):
        raise ValidationError("Control characters are not allowed.")
    return value.strip() if isinstance(value, str) else value

class MovieForm(forms.ModelForm):
    class Meta:
        model = Movie
        fields = ('name', 'director', 'cast', 'release_date', 'description', 'image')

    def clean_release_date(self):
        release_date = self.cleaned_data["release_date"]
        if release_date > timezone.localdate():
            raise ValidationError("Release date cannot be in the future.")
        return release_date

    def clean_image(self):
        image = self.cleaned_data.get("image")
        parsed = urlparse(image) if image else None
        if parsed and parsed.scheme != "https":
            raise ValidationError("Image URL must use HTTPS.")
        if parsed and not parsed.path.lower().endswith((".jpg", ".jpeg", ".png", ".webp", ".gif")):
            raise ValidationError("Image URL must point to a supported image file.")
        return image

    def clean_name(self):
        return _reject_control_characters(self.cleaned_data["name"])

    def clean_director(self):
        return _reject_control_characters(self.cleaned_data["director"])

    def clean_cast(self):
        return _reject_control_characters(self.cleaned_data["cast"])

    def clean_description(self):
        return _reject_control_characters(self.cleaned_data["description"])


class ReviewForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ("comment", "rating")
        error_messages = {
            "comment": {
                "required": "Review comment is required.",
            },
        }

    def clean_comment(self):
        comment = self.cleaned_data.get("comment")
        if not comment or not comment.strip():
            raise ValidationError("Review comment is required.")
        return _reject_control_characters(comment)


class RegisterForm(UserCreationForm):
"""
    Secure registration form extending Django's built-in UserCreationForm.
 
    SECURE CODING [SC-1] Leveraging Trusted Framework Components:
        UserCreationForm enforces password confirmation (password1 == password2)
        and automatically applies every validator listed in AUTH_PASSWORD_VALIDATORS
        (settings.py), including minimum length and common-password checks.
        This avoids re-implementing password logic from scratch.
 
    SECURE CODING [SC-2] Input Validation (server-side):
        All clean_* methods enforce constraints server-side, regardless of any
        client-side checks, so they cannot be bypassed via direct HTTP requests.
    """

    """
    SECURE CODING [SC-3] Require a valid email format.
    EmailField applies RFC 5322 syntax validation automatically.
    """
    email = forms.EmailField(
            required=True,
            help_text="A valid email address is required.",
    )
    
    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def clean_email(self):
        """
        SECURE CODING [SC-4] Prevent duplicate accounts sharing the same email.
        Duplicate emails can enable account-takeover or user-enumeration vectors.
        This check runs server-side after the field's built-in format validation.
        """
        email = self.cleaned_data.get("email", "").lower() # normalise to lowercase
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError(
                "An account with this email already exists."
            )
        return email

    def clean_username(self):
        """
        SECURE CODING [SC-5] Enforce minimum username length and disallow
        leading/trailing whitespace that could cause identity-confusion issues.
        """
        username = self.cleaned_data.get("username", "").strip()
        if len(username) < 3:
            raise forms.ValidationError(
                "Username must be at least 3 characters long.")
            return username
        
    def save(self, commit=True):
         """
        SECURE CODING [SC-6] Use create_user() (via super().save()) which calls
        set_password() internally, ensuring the password is hashed with
        PBKDF2+SHA256 before it is ever written to the database.
        Plain-text passwords are never persisted.
        """
        return super().save(commit=commit)

class LoginForm(AuthenticationForm):
    """
    SECURE CODING [SC-7] Re-use the battle-tested AuthenticationForm rather
    than writing custom credential-checking logic.  AuthenticationForm already:
      • performs constant-time password comparison (mitigates timing attacks),
      • issues a generic error message for any failed authentication attempt
        (prevents username enumeration), and
      • checks that the account is active before returning a user object.
    """
    username = forms.CharField(
        label="Username",
        widget=forms.TextInput(attrs={"autofocus": True}),
    )
    password = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
