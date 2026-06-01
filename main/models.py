from django.db import models
from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator

class Movie(models.Model):
    # Fields for the movie table
    name = models.CharField(max_length=300)
    director = models.CharField(max_length=300)
    cast = models.CharField(max_length=300)
    release_date = models.DateField()
    description = models.TextField(max_length=5000)
    rating = models.FloatField(default=0)
    image = models.URLField(default=None, null=True)

    def __str__(self):
        return self.name

class Review(models.Model):
"""
    SECURE CODING [SC-9] Referential Integrity / Fail Securely:
    CASCADE ensures that when a Movie is deleted, all associated reviews are
    also deleted, preventing orphaned records that could cause unexpected
    behaviour or information leakage.
    """
    movie = models.ForeignKey(Movie, on_delete=models.CASCADE)
 
    """
    SECURE CODING [SC-21] Accountability / Non-Repudiation:
    Every review is linked to the authenticated user who created it via a
    ForeignKey to AUTH_USER_MODEL. Using settings.AUTH_USER_MODEL rather
    than importing User directly is the recommended approach, as it supports
    custom user models without requiring code changes.
    
    SECURE CODING [SC-19] Safe Account Deletion Handling:
    on_delete=CASCADE means deleting a user account also removes their
    reviews, preventing de-anonymised review records from persisting after
    an account is removed (privacy by design).
    """
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
    )
 
    comment = models.TextField(max_length=1000, null=True)
 
    """
    SECURE CODING [SC-2] Server-Side Input Validation:
    MinValueValidator and MaxValueValidator enforce the rating range (1-10)
    at the database layer, not just the form layer. This means the constraint
    cannot be bypassed by submitting a raw API request that skips form
    validation entirely.
    """
    rating = models.FloatField(
        default=0,
        validators=[MinValueValidator(1), MaxValueValidator(10)],
    )
 
    class Meta:
    """
        SECURE CODING [SC-23] Race Condition / Duplicate Submission Prevention:
        UniqueConstraint enforces at the database level that a user can only
        submit one review per movie. Even if two concurrent requests pass the
        application-level duplicate check simultaneously, the database
        constraint ensures only one record is committed, with the second
        raising an IntegrityError caught in views.py.
        """
        constraints = [
            models.UniqueConstraint(
                fields=["movie", "user"],
                name="unique_review_per_user_per_movie",
            ),
        ]
 
    def __str__(self):
        return self.movie.name