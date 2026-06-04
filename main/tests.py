# SECURITY TASK 7 & TASK 9
# Security-focused test suite used to validate authentication,
# authorisation, input validation, CSRF protection, access control,
# review ownership, and administrative permissions.
# Each test is mapped to a specific security requirement and verifies
# that the implemented controls behave as expected.

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.template.context import BaseContext
from django.test import Client, TestCase
from django.urls import reverse

from .models import Movie, Review


def _copy_django_context_for_python_314(self):
    duplicate = object.__new__(self.__class__)
    duplicate.__dict__.update(self.__dict__)
    duplicate.dicts = self.dicts[:]
    return duplicate


# Test harness compatibility: Django 4.1's BaseContext.__copy__ is not compatible with Python 3.14.
BaseContext.__copy__ = _copy_django_context_for_python_314

# SECURITY TASK 7:
# Tests authentication and authorisation requirements including login,
# logout, password validation, session handling, and access control.
class AuthenticationSecurityTests(TestCase):
    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(username="reviewer", password="StrongPass123")
        self.other_user = self.user_model.objects.create_user(username="other", password="StrongPass123")
        self.staff = self.user_model.objects.create_user(
            username="staff", password="StrongPass123", is_staff=True
        )
        self.movie = Movie.objects.create(
            name="Security Movie",
            director="Director",
            cast="Cast",
            release_date="2024-01-01",
            description="A test movie",
            image="https://example.com/movie.jpg",
        )
        self.valid_movie_data = {
            "name": "New Movie",
            "director": "New Director",
            "cast": "New Cast",
            "release_date": "2024-02-02",
            "description": "New description",
            "image": "https://example.com/new.jpg",
        }

    def test_security_anonymous_user_cannot_get_addmovies_without_login(self):
        """Security requirement: anonymous users must not access the Add Movies form."""
        response = self.client.get(reverse("main:add_movies"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("main:login"), response["Location"])

    def test_security_anonymous_user_can_view_login_form(self):
        """Security requirement: anonymous users can access the login form."""
        response = self.client.get(reverse("main:login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Login")

    def test_security_logged_in_user_is_redirected_away_from_login_form(self):
        """Security requirement: authenticated users must not see the login form again."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:login"))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("main:home"))

    def test_security_logged_in_user_cannot_login_as_another_identity_without_logout(self):
        """Security requirement: authenticated users cannot switch identity through /login/."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:login"),
            data={"username": "other", "password": "StrongPass123"},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], reverse("main:home"))
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.id)

    def test_security_anonymous_user_cannot_post_addmovies(self):
        """Security requirement: anonymous users must not submit Add Movies."""
        response = self.client.post(reverse("main:add_movies"), data=self.valid_movie_data)

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Movie.objects.filter(name="New Movie").exists())

    def test_security_logged_in_non_staff_user_cannot_add_movies(self):
        """Security requirement: least privilege permits only staff/admin movie creation."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(reverse("main:add_movies"), data=self.valid_movie_data)

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Movie.objects.filter(name="New Movie").exists())

    def test_security_staff_user_can_add_movie_with_valid_data(self):
        """Security requirement: authorised staff users can create movies."""
        self.client.login(username="staff", password="StrongPass123")
        response = self.client.post(reverse("main:add_movies"), data=self.valid_movie_data)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(Movie.objects.filter(name="New Movie").exists())

    def test_security_anonymous_user_cannot_post_review(self):
        """Security requirement: anonymous users must not submit reviews."""
        response = self.client.post(
            reverse("main:add_review", args=[self.movie.id]),
            data={"comment": "Good", "rating": 8},
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Review.objects.exists())

    def test_security_logged_in_user_can_post_valid_review(self):
        """Security requirement: logged-in users can submit valid reviews."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:add_review", args=[self.movie.id]),
            data={"comment": "Good", "rating": 8},
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(Review.objects.count(), 1)

    def test_security_review_is_linked_to_request_user(self):
        """Security requirement: reviews are accountable to the authenticated user."""
        self.client.login(username="reviewer", password="StrongPass123")
        self.client.post(
            reverse("main:add_review", args=[self.movie.id]),
            data={"comment": "Good", "rating": 8},
        )

        self.assertEqual(Review.objects.get().user, self.user)
# SECURITY TASK 7/9:
# Verifies the application fails securely by returning HTTP 404
# for invalid object identifiers instead of exposing internal
# application errors or stack traces.
    def test_security_invalid_movie_id_returns_404_not_500(self):
        """Security requirement: invalid object IDs fail securely."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:add_review", args=[99999]),
            data={"comment": "Good", "rating": 8},
        )

        self.assertEqual(response.status_code, 404)

    def test_security_invalid_addmovies_post_returns_form_errors_not_500(self):
        """Security requirement: invalid Add Movies POST re-renders validation errors."""
        self.client.login(username="staff", password="StrongPass123")
        response = self.client.post(
            reverse("main:add_movies"),
            data={"name": "", "release_date": "not-a-date"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "name", "This field is required.")
        self.assertEqual(Movie.objects.count(), 1)

    def test_security_future_release_date_is_rejected(self):
        """Security requirement: future release dates are rejected server-side."""
        self.client.login(username="staff", password="StrongPass123")
        data = {**self.valid_movie_data, "release_date": "2045-01-01"}
        response = self.client.post(reverse("main:add_movies"), data=data)

        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response.context["form"],
            "release_date",
            "Release date cannot be in the future.",
        )
        self.assertFalse(Movie.objects.filter(name="New Movie").exists())

    def test_security_untrusted_image_url_is_rejected(self):
        """Security requirement: untrusted/non-HTTPS image URLs are rejected server-side."""
        self.client.login(username="staff", password="StrongPass123")
        data = {**self.valid_movie_data, "image": "http://example.com/new.jpg"}
        response = self.client.post(reverse("main:add_movies"), data=data)

        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "image", "Image URL must use HTTPS.")
        self.assertFalse(Movie.objects.filter(name="New Movie").exists())

    def test_security_review_rating_bounds_are_enforced_server_side(self):
        """Security requirement: direct POSTs cannot submit out-of-policy ratings."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:add_review", args=[self.movie.id]),
            data={"comment": "Bad rating", "rating": 999},
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(Review.objects.exists())

    def test_security_details_invalid_movie_id_returns_404_not_500(self):
        """Security requirement: invalid details IDs fail securely."""
        response = self.client.get(reverse("main:details", args=[99999]))

        self.assertEqual(response.status_code, 404)

    def test_security_details_page_renders_without_removed_trailer_field(self):
        """Security requirement: templates must not depend on removed model fields."""
        response = self.client.get(reverse("main:details", args=[self.movie.id]))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "youtube.com/embed")

    def test_security_post_without_csrf_is_blocked(self):
        """Security requirement: CSRF protection remains enabled for state-changing POSTs."""
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.login(username="staff", password="StrongPass123")
        response = csrf_client.post(reverse("main:add_movies"), data=self.valid_movie_data)

        self.assertEqual(response.status_code, 403)
        self.assertFalse(Movie.objects.filter(name="New Movie").exists())
# SECURITY TASK 7/9:
# Verifies review creation is restricted to POST requests.
# HTTP 405 prevents state-changing actions from being executed
# through unintended request methods.
    def test_security_get_to_addreview_does_not_create_review(self):
        """Security requirement: review creation is method-restricted to POST."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:add_review", args=[self.movie.id]))

        self.assertEqual(response.status_code, 405)
        self.assertFalse(Review.objects.exists())

    def test_security_duplicate_review_by_same_user_is_rejected(self):
        """Security requirement: duplicate reviews by the same user are rejected."""
        self.client.login(username="reviewer", password="StrongPass123")
        self.client.post(
            reverse("main:add_review", args=[self.movie.id]),
            data={"comment": "Good", "rating": 8},
        )
        response = self.client.post(
            reverse("main:add_review", args=[self.movie.id]),
            data={"comment": "Second", "rating": 7},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(Review.objects.filter(movie=self.movie, user=self.user).count(), 1)
# SECURITY TASK 9:
# Verifies administrator-only access control for movie deletion.
    def test_security_anonymous_user_cannot_delete_movie(self):
        """Security requirement: anonymous users must not delete movies."""
        response = self.client.post(reverse("main:delete_movie", args=[self.movie.id]))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(Movie.objects.filter(id=self.movie.id).exists())

    def test_security_logged_in_non_staff_user_cannot_delete_movie(self):
        """Security requirement: only staff/admin users can delete movies."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(reverse("main:delete_movie", args=[self.movie.id]))

        self.assertEqual(response.status_code, 403)
        self.assertTrue(Movie.objects.filter(id=self.movie.id).exists())
# SECURITY TASK 9:
# Verifies movie deletion is restricted to POST requests.
# HTTP 405 helps protect against accidental or malicious
# deletion attempts using GET requests.
    def test_security_staff_user_can_delete_movie(self):
        """Security requirement: staff/admin users can delete movies."""
        self.client.login(username="staff", password="StrongPass123")
        response = self.client.post(reverse("main:delete_movie", args=[self.movie.id]))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Movie.objects.filter(id=self.movie.id).exists())

    def test_security_get_to_delete_movie_does_not_delete_movie(self):
        """Security requirement: movie deletion is method-restricted to POST."""
        self.client.login(username="staff", password="StrongPass123")
        response = self.client.get(reverse("main:delete_movie", args=[self.movie.id]))

        self.assertEqual(response.status_code, 405)
        self.assertTrue(Movie.objects.filter(id=self.movie.id).exists())
# SECURITY TASK 9:
# Verifies administrator-only review moderation and deletion controls.
    def test_security_anonymous_user_cannot_delete_review(self):
        """Security requirement: anonymous users must not delete reviews."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Bad", rating=1)
        response = self.client.post(reverse("main:delete_review", args=[review.id]))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(Review.objects.filter(id=review.id).exists())

    def test_security_logged_in_non_staff_user_cannot_delete_review(self):
        """Security requirement: only staff/admin users can delete reviews."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Bad", rating=1)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(reverse("main:delete_review", args=[review.id]))

        self.assertEqual(response.status_code, 403)
        self.assertTrue(Review.objects.filter(id=review.id).exists())

    def test_security_staff_user_can_delete_review(self):
        """Security requirement: staff/admin users can delete invalid reviews."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Bad", rating=1)
        self.client.login(username="staff", password="StrongPass123")
        response = self.client.post(reverse("main:delete_review", args=[review.id]))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Review.objects.filter(id=review.id).exists())
# SECURITY TASK 9:
# Verifies review deletion is restricted to POST requests.
# HTTP 405 enforces method restrictions and supports CSRF protection.
    def test_security_get_to_delete_review_does_not_delete_review(self):
        """Security requirement: review deletion is method-restricted to POST."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Bad", rating=1)
        self.client.login(username="staff", password="StrongPass123")
        response = self.client.get(reverse("main:delete_review", args=[review.id]))

        self.assertEqual(response.status_code, 405)
        self.assertTrue(Review.objects.filter(id=review.id).exists())
# SECURITY TASK 9:
# Verifies review-history privacy controls and ensures users can only
# access their own review information.
    def test_security_anonymous_user_cannot_access_my_reviews(self):
        """Security requirement: anonymous users are redirected from private review history."""
        response = self.client.get(reverse("main:my_reviews"))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("main:login"), response["Location"])

    def test_security_logged_in_user_can_access_my_reviews(self):
        """Security requirement: authenticated users can access their own review history."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:my_reviews"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "My Reviews")

    def test_security_my_reviews_only_shows_request_user_reviews(self):
        """Security requirement: privacy by design shows only request.user's reviews."""
        Review.objects.create(movie=self.movie, user=self.user, comment="Own private review", rating=8)
        Review.objects.create(movie=self.movie, user=self.other_user, comment="Other private review", rating=4)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:my_reviews"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Own private review")
        self.assertNotContains(response, "Other private review")

    def test_security_my_reviews_does_not_accept_other_user_id(self):
        """Security requirement: IDOR prevention ignores user-controlled IDs."""
        Review.objects.create(movie=self.movie, user=self.other_user, comment="Other user review", rating=4)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:my_reviews"), {"user_id": self.other_user.id})

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Other user review")

    def test_security_my_reviews_empty_state_renders_safely(self):
        """Security requirement: empty private review history renders a safe empty state."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:my_reviews"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "You have not written any reviews yet.")
# SECURITY TASK 9:
# Verifies ownership-based authorisation and IDOR prevention
# for review editing functionality.
    def test_security_anonymous_user_cannot_access_edit_review(self):
        """Security requirement: anonymous users are redirected from review editing."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Own review", rating=8)
        response = self.client.get(reverse("main:edit_review", args=[review.id]))

        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("main:login"), response["Location"])

    def test_security_user_can_access_edit_form_for_own_review(self):
        """Security requirement: owners can access the edit form for their own review."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Own review", rating=8)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:edit_review", args=[review.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Edit Review")
        self.assertContains(response, "Own review")

    def test_security_user_can_successfully_edit_own_review(self):
        """Security requirement: owners can update their own review after server-side validation."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Old review", rating=8)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:edit_review", args=[review.id]),
            data={"comment": "Updated review", "rating": 9},
        )

        review.refresh_from_db()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(review.comment, "Updated review")
        self.assertEqual(review.rating, 9)

    def test_security_user_cannot_edit_another_users_review(self):
        """Security requirement: ownership-based authorisation blocks editing another user's review."""
        review = Review.objects.create(movie=self.movie, user=self.other_user, comment="Other review", rating=4)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:edit_review", args=[review.id]),
            data={"comment": "Tampered review", "rating": 10},
        )

        review.refresh_from_db()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(review.comment, "Other review")
        self.assertEqual(review.rating, 4)

    def test_security_invalid_edit_review_id_returns_404(self):
        """Security requirement: invalid edit review IDs fail securely with 404."""
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:edit_review", args=[99999]))

        self.assertEqual(response.status_code, 404)

    def test_security_invalid_edit_review_form_does_not_update_review(self):
        """Security requirement: invalid edit input re-renders errors and preserves existing review."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Old review", rating=8)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.post(
            reverse("main:edit_review", args=[review.id]),
            data={"comment": "", "rating": 999},
        )

        review.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "comment", "Review comment is required.")
        self.assertEqual(review.comment, "Old review")
        self.assertEqual(review.rating, 8)

    def test_security_edited_review_remains_linked_to_original_owner(self):
        """Security requirement: edit POST cannot change review ownership."""
        review = Review.objects.create(movie=self.movie, user=self.user, comment="Old review", rating=8)
        self.client.login(username="reviewer", password="StrongPass123")
        self.client.post(
            reverse("main:edit_review", args=[review.id]),
            data={"comment": "Updated review", "rating": 9, "user": self.other_user.id},
        )

        review.refresh_from_db()
        self.assertEqual(review.user, self.user)

    def test_security_edit_link_is_visible_only_for_review_owner(self):
        """Security requirement: edit links are shown only to the owner of each review."""
        own_review = Review.objects.create(movie=self.movie, user=self.user, comment="Own review", rating=8)
        other_review = Review.objects.create(movie=self.movie, user=self.other_user, comment="Other review", rating=4)
        self.client.login(username="reviewer", password="StrongPass123")
        response = self.client.get(reverse("main:details", args=[self.movie.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("main:edit_review", args=[own_review.id]))
        self.assertNotContains(response, reverse("main:edit_review", args=[other_review.id]))
# SECURITY TASK 7:
# Verifies custom password-strength requirements are enforced server-side.
    def test_security_password_requires_length_capital_number_and_special_character(self):
        """Security requirement: passwords need 8 chars, one capital, one number, and one special char."""
        invalid_passwords = ["A1!", "password1!", "Password!", "Password1"]

        for password in invalid_passwords:
            with self.subTest(password=password):
                with self.assertRaises(ValidationError):
                    validate_password(password)

    def test_security_password_can_be_similar_to_username(self):
        """Security requirement: similar passwords are allowed if they satisfy the strength rule."""
        similar_user = self.user_model(username="SimilarName")

        validate_password("SimilarName1!", user=similar_user)
