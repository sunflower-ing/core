import uuid

from django.http import HttpResponse
from django.shortcuts import redirect, render

from .models import (
    ALGO_CHOICES,
    CRL,
    CSR,
    LENGTH_CHOICES,
    REVOCATION_CHOICES,
    Certificate,
    Key,
)


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
    csr = CSR.objects.get(id=csr_id)
    ctx = {"csr": csr, "certificate": csr.certificate_set.all().first()}
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
            "extendedKeyUsage": request.POST.get("extendedKeyUsage"),
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
            "issuerDN": bool(request.POST.get("issuerDN", False)),
            "days": int(request.POST.get("days", 365)),
            "CRLDistributionPoints": request.POST.get("CRLDistributionPoints"),
            "AuthorityInformationAccess": request.POST.get(
                "AuthorityInformationAccess"
            ),
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
            return redirect("x509:csr_detail", csr_id=csr.id)

        except Exception as e:
            ctx.update({"error": str(e)})

    return render(request, "x509/csr_new.html", ctx)


def certificates_list(request):
    certificates = Certificate.objects.order_by("-created_at")
    ctx = {"certificates_list": certificates}
    return render(request, "x509/certs_list.html", ctx)


def certificate_detail(request, certificate_id):
    certificate = Certificate.objects.get(id=certificate_id)
    ctx = {"certificate": certificate}
    return render(request, "x509/cert_detail.html", ctx)


def certificate_new(request):
    ctx = {
        "available_csrs": CSR.objects.filter(signed=False),
        "available_cas": Certificate.objects.filter(csr__ca=True),
        "csr": int(request.POST.get("csr", request.GET.get("csr_id", 0))),
        "ca": int(request.POST.get("ca", 0)),
    }

    if request.POST:
        try:
            csr = CSR.objects.get(id=ctx["csr"])

            parent = None
            if ctx["ca"] > 0:
                parent = Certificate.objects.get(id=ctx["ca"])

            certificate = Certificate(csr=csr, parent=parent)
            certificate.save()

            return redirect(
                "x509:certificate_detail", certificate_id=certificate.id
            )

        except Exception as e:
            ctx.update({"error": str(e)})

    return render(request, "x509/cert_new.html", ctx)


def certificate_revoke(request, certificate_id):
    certificate = Certificate.objects.get(id=certificate_id)
    ctx = {"certificate": certificate, "reason_options": REVOCATION_CHOICES}

    if request.POST:
        certificate.revoke()
        return redirect(
            "x509:certificate_detail", certificate_id=certificate_id.id
        )

    return render(request, "x509/cert_revoke.html", ctx)


def crl(request, ca_slug):
    crl = CRL.objects.filter(ca__csr__slug=ca_slug).first()
    return HttpResponse(crl.body)
