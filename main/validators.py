# SECURITY TASK 7:
# Custom password-strength validation implementing the authentication
# requirements specified in Task 5. This validator enforces password
# complexity rules to reduce the risk of weak passwords, credential
# guessing, and brute-force attacks.

import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

# SECURITY TASK 7: Custom password validator enforcing stronger password requirements.
# Prevents weak passwords by requiring a minimum length, uppercase letter,
# number, and special character.
class StrongPasswordValidator:
    def validate(self, password, user=None):
        if len(password) < 8:
            raise ValidationError(
                _("Password must be at least 8 characters long."),
                code="password_too_short",
            )
        # SECURITY TASK 7: Requires at least one uppercase character to
        # increase password complexity.
        if not re.search(r"[A-Z]", password):
            raise ValidationError(
                _("Password must contain at least one capital letter."),
                code="password_no_capital",
            )
        # SECURITY TASK 7: Requires at least one numeric character to
        # reduce the likelihood of easily guessed passwords.
        if not re.search(r"\d", password):
            raise ValidationError(
                _("Password must contain at least one number."),
                code="password_no_number",
            )
        # SECURITY TASK 7: Requires at least one special character to
        # strengthen password entropy and complexity.
        if not re.search(r"[^A-Za-z0-9]", password):
            raise ValidationError(
                _("Password must contain at least one special character."),
                code="password_no_special",
            )
# SECURITY TASK 7: Provides users with clear password requirements,
 # encouraging secure password creation and reducing validation errors.
    def get_help_text(self):
        return _(
            "Your password must be at least 8 characters long and contain "
            "one capital letter, one number, and one special character."
        )
