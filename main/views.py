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


class UserLoginView(LoginView):
    template_name = "main/login.html"
    # Secure coding principle: session clarity. Authenticated users are redirected
    # away from the login form to prevent accidental identity switching without logout.
    redirect_authenticated_user = True


def register_view(request):
    """
    User registration view.
 
    SECURE CODING [SC-12] Redirect already-authenticated users:
        Prevents a logged-in user from registering a second account via direct
        URL access, reducing account-confusion risks.
    """
    if request.user.is_authenticated:
        return redirect("main:home")
 
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            # Password hashing (see forms.py SC-6).
            # form.save() calls set_password() → PBKDF2+SHA256 hash stored.
            user = form.save()
 
            # Session Fixation Prevention:
            #   login() calls cycle_key() which issues a brand-new session ID.
            #   An attacker who obtained the pre-login session token cannot
            #   reuse it after the user authenticates.  REF: [3], [5]
            login(request, user)
            messages.success(request, "Registration successful. Welcome!")
            return redirect("main:home")
        else:
            # SECURE CODING [SC-14] — Generic failure message:
            #   Individual field errors are rendered inside the form, but the
            #   top-level message does not reveal which specific field failed,
            #   limiting information leakage.
            messages.error(request, "Registration failed. Please correct the errors below.")
    else:
        form = RegisterForm()
 
    return render(request, "main/register.html", {"form": form})


def home(request):
    """
    SECURE CODING [SC-8] SQL Injection Prevention:
        The Django ORM generates parameterised SQL queries; user-supplied
        search input is never interpolated directly into a query string.
    """
    query = request.GET.get("title", "").strip()
    if query:
        # ORM parameterised query — safe from SQL injection
        allMovies = Movie.objects.filter(name__icontains=query)
    else:
        allMovies = Movie.objects.all()
 
    return render(request, "main/index.html", {"movies": allMovies})


# detail page
def details(request, id):
    """
    SECURE CODING [SC-9] Use get_object_or_404 instead of get().
        A bare .get() raises an unhandled exception that can leak stack-trace
        information.  get_object_or_404 returns a safe 404 response with no
        internal details exposed.  REF: [4]
    """
    movie = get_object_or_404(Movie, id=id)
    reviews = Review.objects.filter(movie=movie).order_by("-id")
    return render(request, "main/details.html", {"movie": movie, "reviews": reviews})

# add movies to database
@login_required
def add_movies(request):
    # Secure coding principle: server-side authorisation. The UI hiding the button is not trusted.
    # Secure coding principle: least privilege and deny by default. Only staff users can create movies.
    if not request.user.is_staff:
        return HttpResponseForbidden("Only staff users can add movies.")

    if request.method == "POST":
        form = MovieForm(request.POST)
        # check if the form is valid
        if form.is_valid():
            form.save()
            return redirect("main:home")
    else:
        form = MovieForm()

    return render(request, 'main/addmovies.html', {"form": form})


@login_required
@require_POST
def delete_movie(request, id):
    # Secure coding principle: server-side authorisation. Only staff users can delete movies.
    # Secure coding principle: method restriction. Deletion is POST-only and protected by CSRF.
    if not request.user.is_staff:
        return HttpResponseForbidden("Only staff users can delete movies.")

    movie = get_object_or_404(Movie, id=id)
    movie.delete()
    return redirect("main:home")


@login_required
@require_POST
def delete_review(request, id):
    # Secure coding principle: server-side authorisation. Only staff users can moderate reviews.
    # Secure coding principle: method restriction. Review deletion is POST-only and CSRF-protected.
    if not request.user.is_staff:
        return HttpResponseForbidden("Only staff users can delete reviews.")

    review = get_object_or_404(Review, id=id)
    movie_id = review.movie_id
    review.delete()
    return redirect("main:details", id=movie_id)


@login_required
def my_reviews(request):
    # Secure coding principle: server-side access control. Review history requires authentication.
    # Secure coding principle: privacy by design / data minimisation. Only request.user's reviews are shown.
    # Secure coding principle: IDOR prevention. No user_id is accepted from URL, query string, or POST data.
    reviews = Review.objects.filter(user=request.user).select_related("movie").order_by("-id")
    return render(request, "main/myreviews.html", {"reviews": reviews})


@login_required
def edit_review(request, id):
    # Secure coding principle: fail securely. Invalid review IDs return 404.
    review = get_object_or_404(Review.objects.select_related("movie", "user"), id=id)

    # Secure coding principle: ownership-based authorisation and server-side enforcement.
    # UI visibility is not trusted; only the original owner can edit the review.
    if review.user != request.user:
        return HttpResponseForbidden("You can only edit your own reviews.")

    if request.method == "POST":
        # Secure coding principle: input validation. Rating and comment are validated server-side.
        form = ReviewForm(request.POST, instance=review)
        if form.is_valid():
            updated_review = form.save(commit=False)
            # Secure coding principle: accountability. Ownership is preserved and never taken from client input.
            updated_review.user = review.user
            updated_review.movie = review.movie
            updated_review.save()
            return redirect("main:details", id=review.movie_id)
    else:
        form = ReviewForm(instance=review)

    return render(request, "main/editreview.html", {"form": form, "review": review})


#review
@login_required
@require_POST
def add_review(request, id):
    # Secure coding principle: method restriction. Review creation is POST-only.
    # Secure coding principle: fail securely. Invalid movie IDs return 404 instead of 500.
    movie = get_object_or_404(Movie, id=id)
    form = ReviewForm(request.POST)

    if Review.objects.filter(movie=movie, user=request.user).exists():
        form.add_error(None, "You have already reviewed this movie.")
    elif form.is_valid():
        data = form.save(commit=False)
        data.movie = movie
        # Secure coding principle: accountability. Reviews are linked to the authenticated user.
        # Secure coding principle: server-side enforcement. The submitted user value is never trusted.
        data.user = request.user
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
