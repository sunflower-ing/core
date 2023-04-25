from django.http import HttpResponse
from django.shortcuts import render, redirect

from .models import ALGO_CHOICES, LENGTH_CHOICES, Key


def certificates_list(request):
    return HttpResponse("Hello, world. You're at the polls index.")


def certificate_detail(request, certificate_id):
    return HttpResponse("Hello, world. You're at the polls index.")


def keys_list(request):
    keys = Key.objects.order_by("-created_at")
    ctx = {"keys_list": keys}
    return render(request, "x509/keys_list.html", ctx)


def key_detail(request, key_id):
    ctx = {
        "key": Key.objects.get(id=key_id),
    }
    return render(request, "x509/key_detail.html", ctx)


def key_new(request):
    ctx = {
        "name": request.POST.get("name", ""),
        "algo": request.POST.get("algo"),
        "length": request.POST.get("length"),
        "algo_options": ALGO_CHOICES,
        "length_options": LENGTH_CHOICES,
    }

    if request.POST:
        try:
            key = Key(
                name=ctx["name"], algo=ctx["algo"], length=int(ctx["length"])
            )
            key.save()
            return redirect("x509:key_detail", key_id=key.id)

        except Exception as e:
            ctx.update({"error": str(e)})

    return render(request, "x509/key_new.html", ctx)


def csr_list(request):
    return HttpResponse("Hello, world. You're at the polls index.")


def csr_detail(request, csr_id):
    return HttpResponse("Hello, world. You're at the polls index.")


def csr_new(request):
    return HttpResponse("Hello, world. You're at the polls index.")
