from django.http import HttpResponse
from django.shortcuts import redirect, render
import uuid
from .models import ALGO_CHOICES, CSR, LENGTH_CHOICES, Key


def certificates_list(request):
    return HttpResponse("Hello, world. You're at the polls index.")


def certificate_detail(request, certificate_id):
    return HttpResponse("Hello, world. You're at the polls index.")


def keys_list(request):
    keys = Key.objects.order_by("-created_at")
    ctx = {"keys_list": keys}
    return render(request, "x509/keys_list.html", ctx)


def key_detail(request, key_id):
    key = Key.objects.get(id=key_id)
    ctx = {"key": key, "csr": key.csr_set.all().first()}
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
    csrs = CSR.objects.order_by("-created_at")
    ctx = {"csrs_list": csrs}
    return render(request, "x509/csrs_list.html", ctx)


def csr_detail(request, csr_id):
    ctx = {"csr": CSR.objects.get(id=csr_id)}
    return render(request, "x509/csr_detail.html", ctx)


def csr_new(request):
    ctx = {
        "available_keys": Key.objects.filter(used=False).order_by(
            "-created_at"
        ),
        "key": int(request.POST.get("key", 0)),
        "name": request.POST.get("name", ""),
        "ca": bool(request.POST.get("ca", False)),
        "path_length": int(request.POST.get("path_length", 0)),
        "params": {
            # Type
            "extendedKeyUsage": request.POST.get(
                "extendedKeyUsage", "client_auth"
            ),
            # DN
            "countryName": request.POST.get("countryName", ""),
            "stateOrProvinceName": request.POST.get("stateOrProvinceName", ""),
            "localityName": request.POST.get("localityName", ""),
            "organizationName": request.POST.get("organizationName", ""),
            "organizationUnitName": request.POST.get(
                "organizationUnitName", ""
            ),
            "commonName": request.POST.get("commonName", ""),
            "emailAddress": request.POST.get("emailAddress", ""),
            "givenName": request.POST.get("givenName", ""),
            "surname": request.POST.get("surname", ""),
            # Others
            "takeFromIssuer": bool(request.POST.get("takeFromIssuer", False)),
        },
    }

    if request.POST:
        try:
            if ctx["key"] > 0:
                key = Key.objects.get(id=ctx["key"])
            else:
                key = Key(name=str(uuid.uuid4()))
                key.save()

            csr = CSR(
                key=key,
                name=ctx["name"],
                ca=ctx["ca"],
                path_length=ctx["path_length"],
                params=ctx["params"],
            )
            csr.save()
            return redirect("x509:key_detail", key_id=key.id)

        except Exception as e:
            ctx.update({"error": str(e)})

    return render(request, "x509/csr_new.html", ctx)
