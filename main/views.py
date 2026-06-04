from django.contrib.auth import login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.db import IntegrityError, transaction
from django.http import HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .forms import MovieForm, RegisterForm, ReviewForm
from .models import Movie, Review
# Create your views here.

# SECURITY TASK 7: Uses Django's built-in LoginView for authentication instead of custom password handling.
# Django handles credential checking, session creation, and safe login failure messages.
class UserLoginView(LoginView): 
    """
    SECURE CODING [SC-12] Redirect Already-Authenticated Users:
    Authenticated users are redirected away from the login form to prevent
    accidental identity switching without an explicit logout first.
    redirect_authenticated_user = True
 
    SECURE CODING [SC-13] Session Fixation Prevention:
    LoginView calls login() internally, which calls session.cycle_key(),
    issuing a brand-new session ID on successful authentication.
    An attacker who obtained the pre-login session token cannot reuse it.
 
    SECURE CODING [SC-15] Constant-Time Credential Comparison:
    LoginView uses AuthenticationForm, which calls authenticate() internally.
    authenticate() uses hmac.compare_digest() for password comparison so an
    attacker cannot infer correctness from response timing.
 
    SECURE CODING [SC-17] Username Enumeration Prevention:
    AuthenticationForm returns the same generic error whether the username
    does not exist OR the password is wrong, so an attacker cannot
    distinguish between the two outcomes.
    """
    # SECURITY TASK 7: Redirects users who are already logged in away from the login page
    # to reduce accidental session/account confusion.
template_name = "main/login.html"
redirect_authenticated_user = True

# SECURITY TASK 7: Registration uses Django form validation and built-in password hashing.
# Passwords are never manually stored or saved in plain text.
def register(request):
    """
    SECURE CODING [SC-12] Redirect Already-Authenticated Users:
    Prevents a logged-in user from registering a second account via direct
    URL access, reducing account-confusion risks.
    """
    # SECURITY TASK 7: Prevents already-authenticated users from creating another account
    # without intentionally logging out first.
    if request.user.is_authenticated:
        return redirect("main:home")
 
 # SECURITY TASK 7: Validates registration input, including custom password rules,
 # before creating the user account.
    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
    
        """
        SECURE CODING [SC-6] Password Hashing:
        form.save() delegates to create_user(), which calls set_password()
        internally. set_password() hashes the raw password with PBKDF2+SHA256
        before any database write. Plain-text passwords are never persisted.
        """

        # SECURITY TASK 7: form.save() uses Django's user creation process,
        # which hashes the password before writing it to the database.
        user = form.save()
 
        """
        SECURE CODING [SC-13] Session Fixation Prevention:
        auth_login() calls session.cycle_key(), issuing a new session ID so
        a pre-registration token cannot be reused.
        """
        # SECURITY TASK 7: Starts an authenticated session using Django's session framework
        # instead of manually creating session cookies.
        auth_login(request, user)
        return redirect("main:home")
 
    return render(request, "main/register.html", {"form": form})

# SECURITY TASK 7: Logout is restricted to POST requests so it cannot be triggered
# accidentally through a normal link or image request.  
@require_POST
def logout(request):
    """
    SECURE CODING [SC-18] POST-Only Logout:
    @require_POST ensures logout cannot be triggered by a GET request such
    as an embedded <img> or <a> tag on a third-party page (CSRF via GET).
 
    SECURE CODING [SC-19] Full Session Flush on Logout:
    auth_logout() calls session.flush(), which deletes the server-side
    session record and issues a new empty cookie, fully invalidating the
    old token so it cannot be replayed.
    """
    # SECURITY TASK 7: Clears the authenticated session so the old session cannot be reused.
    auth_logout(request)
    return redirect("main:home")

def home(request):
    """
    SECURE CODING [SC-8] SQL Injection Prevention:
    Movie.objects.filter() uses the Django ORM, which generates parameterised
    SQL. User-supplied search input is never interpolated directly into a
    query string.
    """
    query = request.GET.get("title")
    if query:
        allMovies = Movie.objects.filter(name__icontains=query)
    else:
        allMovies = Movie.objects.all()
    return render(request, 'main/index.html', {'movies': allMovies})

# detail page
def details(request, id):
    """
    SECURE CODING [SC-9] Fail Securely / No Stack Trace Leakage:
    get_object_or_404() returns a safe 404 response for invalid IDs instead
    of raising an unhandled exception that would expose a Django stack trace
    containing internal file paths, settings, and ORM queries.
    """
    movie = get_object_or_404(Movie, id=id)
    reviews = Review.objects.filter(movie=movie).select_related("user").order_by("-id")
    reviewed = request.user.is_authenticated and Review.objects.filter(movie=movie, user=request.user).exists()
    return render(
        request,
        'main/details.html',
        {'movie': movie, 'reviews': reviews, 'reviewed': reviewed, 'form': ReviewForm()},
    )
    
# add movies to database
# SECURITY TASK 7/9: Requires login before accessing movie-management functionality.
@login_required
def add_movies(request):
    """
    SECURE CODING [SC-20] Principle of Least Privilege / Access Control:
    @login_required rejects unauthenticated requests before the view body runs.
 
    SECURE CODING [SC-20a] Role-Based Access Control:
    UI-level hiding of the "Add Movie" button is not trusted. The check is
    enforced server-side so a non-staff user cannot bypass it by crafting a
    direct HTTP request.
    """

# SECURITY TASK 7/9: Enforces admin/staff permissions server-side.
# This prevents users bypassing hidden UI controls by directly visiting the URL.
    if not request.user.is_staff:
        return HttpResponseForbidden("Only staff users can add movies.")
 
    if request.method == "POST":
        form = MovieForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("main:home")
    else:
        form = MovieForm()
 
    return render(request, 'main/addmovies.html', {"form": form})

@login_required
@require_POST
def delete_movie(request, id):
    """
    SECURE CODING [SC-20a] Role-Based Access Control (server-side):
    Only staff users can delete movies; enforced server-side regardless of UI.
    """
    if not request.user.is_staff:
        return HttpResponseForbidden("Only staff users can delete movies.")
 
    """
    SECURE CODING [SC-11] HTTP Method Restriction:
    @require_POST ensures deletion cannot be triggered via a GET request,
    preventing CSRF-via-link attacks.  Combined with CsrfViewMiddleware this
    requires a valid CSRF token on every deletion request.
 
    SECURE CODING [SC-9] Fail Securely:
    get_object_or_404() prevents information leakage on invalid IDs.
    """
    movie = get_object_or_404(Movie, id=id)
    movie.delete()
    return redirect("main:home")

@login_required
@require_POST
def delete_review(request, id):
    """
    SECURE CODING [SC-20a] Role-Based Access Control (server-side):
    Only staff users can moderate/delete reviews.
    """
    if not request.user.is_staff:
        return HttpResponseForbidden("Only staff users can delete reviews.")
 
    """
    SECURE CODING [SC-11] HTTP Method Restriction:
    @require_POST ensures deletion is POST-only and CSRF-protected.
 
    SECURE CODING [SC-9] Fail Securely:
    """
    review = get_object_or_404(Review, id=id)
    movie_id = review.movie_id
    review.delete()
    return redirect("main:details", id=movie_id)

# SECURITY TASK 9: Requires authentication before showing review history.
@login_required
def my_reviews(request):
    """
    SECURE CODING [SC-20] Authentication Required:
    @login_required enforces that only authenticated users can view review history.
 
    SECURE CODING [SC-22] IDOR Prevention / Privacy by Design:
    Reviews are filtered exclusively by request.user, which is sourced from
    the server-side session. No user_id is accepted from the URL, query
    string, or POST data, so a user cannot view another user's review history
    by manipulating the request.
    """
    # SECURITY TASK 9: Filters reviews by request.user so users cannot view another user's history.
    reviews = Review.objects.filter(user=request.user).select_related("movie").order_by("-id")
    return render(request, "main/myreviews.html", {"reviews": reviews})

# SECURITY TASK 9: Requires authentication before review editing.
@login_required
def edit_review(request, id):
    """
    SECURE CODING [SC-9] Fail Securely:
    Invalid review IDs return 404 instead of an unhandled exception.
    """
    review = get_object_or_404(Review.objects.select_related("movie", "user"), id=id)
 
    """
    SECURE CODING [SC-22] Ownership-Based Authorisation (IDOR Prevention):
    The owner check is enforced server-side. UI-level hiding of the edit
    button is not trusted; a user who crafts a direct request to another
    user's review ID receives a 403 Forbidden response.
    """
    # SECURITY TASK 9: Prevents IDOR by checking ownership before allowing review edits.
    if review.user != request.user:
        return HttpResponseForbidden("You can only edit your own reviews.")
 
    if request.method == "POST":
        """
        SECURE CODING [SC-2] Server-Side Input Validation:
        Rating and comment are validated through ReviewForm before saving.
        """
        form = ReviewForm(request.POST, instance=review)
        if form.is_valid():
            updated_review = form.save(commit=False)
 
            """
            SECURE CODING [SC-21] Accountability / Non-Repudiation:
            Ownership fields (user, movie) are preserved from the original
            database record and never taken from client input, preventing a
            user from reassigning a review to another user or movie via the
            POST body.
            """
            updated_review.user = review.user
            updated_review.movie = review.movie
            updated_review.save()
            return redirect("main:details", id=review.movie_id)
    else:
        form = ReviewForm(instance=review)
 
    return render(request, "main/editreview.html", {"form": form, "review": review})

# SECURITY TASK 7/9: Requires login and POST-only submission for review creation.
@login_required
@require_POST
def add_review(request, id):
    """
    SECURE CODING [SC-11] HTTP Method Restriction:
    @require_POST ensures review creation is POST-only.
 
    SECURE CODING [SC-9] Fail Securely:
    Invalid movie IDs return 404 instead of an unhandled exception.
    """

    # SECURITY TASK 7/9: Fails safely with a 404 instead of exposing an unhandled server error.
    movie = get_object_or_404(Movie, id=id)
    form = ReviewForm(request.POST)
 
    if Review.objects.filter(movie=movie, user=request.user).exists():
        form.add_error(None, "You have already reviewed this movie.")
    elif form.is_valid():
        data = form.save(commit=False)
        data.movie = movie
 
        """
        SECURE CODING [SC-21] Accountability / Non-Repudiation:
        The review is linked to the authenticated user via request.user,
        sourced from the server-side session. The submitted POST body is
        never trusted for the user value.
        """

        # SECURITY TASK 9: Links the review to the authenticated user from the server-side session.
        # The user value is never accepted from the POST body.
        data.user = request.user
 
        """
        SECURE CODING [SC-23] Race Condition Prevention:
        transaction.atomic() ensures that a duplicate review submitted in a
        concurrent request is caught by the database-level unique constraint
        and surfaces as an IntegrityError rather than creating two records.
        """
        try:
            with transaction.atomic():
                data.save()
        except IntegrityError:
            form.add_error(None, "You have already reviewed this movie.")
        else:
            return redirect("main:details", id=id)
 
    reviews = Review.objects.filter(movie=movie).select_related("user").order_by("-id")
    return render(
        request,
        'main/details.html',
        {"movie": movie, "reviews": reviews, "form": form, "reviewed": False},
    )
 