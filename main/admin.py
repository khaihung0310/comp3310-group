from django.contrib import admin

from .models import Movie, Review


@admin.register(Movie)
class MovieAdmin(admin.ModelAdmin):
    list_display = ("name", "director", "release_date", "rating")
    search_fields = ("name", "director", "cast")


@admin.register(Review)
class ReviewAdmin(admin.ModelAdmin):
    list_display = ("movie", "user", "rating")
    search_fields = ("movie__name", "user__username", "comment")
