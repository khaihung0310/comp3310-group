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
    movie = models.ForeignKey(Movie, on_delete=models.CASCADE)
    # Secure coding principle: accountability. New reviews are linked to the authenticated user.
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True)
    comment = models.TextField(max_length=1000, null=True)
    rating = models.FloatField(default=0, validators=[MinValueValidator(1), MaxValueValidator(10)])

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["movie", "user"], name="unique_review_per_user_per_movie"),
        ]

    def __str__(self):
        return self.movie.name
