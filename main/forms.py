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

    def clean_comment(self):
        comment = self.cleaned_data.get("comment")
        if not comment or not comment.strip():
            raise ValidationError("Review comment is required.")
        return _reject_control_characters(comment)


class RegisterForm(UserCreationForm):
    class Meta:
        model = User
        fields = ("username", "password1", "password2")
