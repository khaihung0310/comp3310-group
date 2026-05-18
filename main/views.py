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


def register(request):
    if request.user.is_authenticated:
        return redirect("main:home")

    form = RegisterForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        auth_login(request, user)
        return redirect("main:home")

    return render(request, "main/register.html", {"form": form})


@require_POST
def logout(request):
    auth_logout(request)
    return redirect("main:home")


def home(request):
    query = request.GET.get("title")
    allMovies = None
    if query:
        allMovies = Movie.objects.filter(name__icontains=query)
    else:
        allMovies = Movie.objects.all()   # select * from movies
    #can use ,context dictionary instead {'movies': allMovies}
    return render(request, 'main/index.html', {'movies': allMovies}) #got error here, instead of using dictionary write in this way


# detail page
def details(request, id):
    # Secure coding principle: fail securely. Invalid object IDs return 404 instead of 500.
    movie = get_object_or_404(Movie, id=id)
    # Retrieve reviews for the specific movie
    reviews = Review.objects.filter(movie=movie).select_related("user").order_by("-id")
    reviewed = request.user.is_authenticated and Review.objects.filter(movie=movie, user=request.user).exists()
    return render(
        request,
        'main/details.html',
        {'movie': movie, 'reviews': reviews, 'reviewed': reviewed, 'form': ReviewForm()},
    )

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
