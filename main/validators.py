import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class StrongPasswordValidator:
    def validate(self, password, user=None):
        if len(password) < 8:
            raise ValidationError(
                _("Password must be at least 8 characters long."),
                code="password_too_short",
            )
        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                _("Password must contain at least one capital letter."),
                code="password_no_capital",
            )
        if not re.search(r"\d", password):
            raise ValidationError(
                _("Password must contain at least one number."),
                code="password_no_number",
            )
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValidationError(
                _("Password must contain at least one special character."),
                code="password_no_special",
            )

    def get_help_text(self):
        return _(
            "Your password must be at least 8 characters long and contain "
            "one capital letter, one number, and one special character."
        )
