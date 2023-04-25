from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from x509.models import CSR, Certificate, Key


@login_required
def index(request):
    response = {
        "key_count": Key.objects.count(),
        "csr_count": CSR.objects.count(),
        "certificate_count": Certificate.objects.count(),
    }
    return render(request, "core/dashboard.html", response)


def login_view(request):
    response = {}

    if request.POST:
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("index")
        else:
            response = {"error": "Authentication failed"}

    return render(request, "login.html", response)


def logout_view(request):
    logout(request)
    return redirect("/")
