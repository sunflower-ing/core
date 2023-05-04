from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography import x509
from django.db import models

from utils.crypto import (
    key_from_pem,
    key_to_pem,
    make_keys,
    make_csr,
    csr_to_pem,
    csr_from_pem,
    make_cert,
    cert_from_pem,
    cert_to_pem,
)

ALGO_RSA = "RSA"
ALGO_DSA = "DSA"
ALGO_CHOICES = ((ALGO_RSA, ALGO_RSA), (ALGO_DSA, ALGO_DSA))

LENGTH_1024 = 1024
LENGTH_2048 = 2048
LENGTH_3072 = 3072
LENGTH_4096 = 4096
LENGTH_8192 = 8192
LENGTH_CHOICES = (
    (LENGTH_1024, f"{LENGTH_1024}"),
    (LENGTH_2048, f"{LENGTH_2048}"),
    (LENGTH_3072, f"{LENGTH_3072}"),
    (LENGTH_4096, f"{LENGTH_4096}"),
    (LENGTH_8192, f"{LENGTH_8192}"),
)


class Key(models.Model):
    name = models.CharField(verbose_name="Internal name", max_length=255)
    private = models.TextField(verbose_name="Private part", blank=True)
    public = models.TextField(verbose_name="Public part", blank=True)
    algo = models.CharField(
        verbose_name="Algorithm",
        max_length=7,
        default=ALGO_RSA,
        choices=ALGO_CHOICES,
    )
    length = models.IntegerField(
        verbose_name="Key length",
        default=LENGTH_4096,
        choices=LENGTH_CHOICES,
        null=True,
    )
    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )

    used = models.BooleanField(verbose_name="Used", default=False)

    def __str__(self) -> str:
        return f"{self.name} {self.algo}({self.length})"

    def save(self, *args, **kwargs) -> None:
        private_key, public_key = make_keys(self.algo, self.length)
        self.private = key_to_pem(private_key, private=True).decode()
        self.public = key_to_pem(public_key).decode()
        return super().save(*args, **kwargs)

    def private_as_object(self) -> rsa.RSAPrivateKey | dsa.DSAPrivateKey:
        return key_from_pem(self.private.encode(), private=True)

    def public_as_object(self) -> rsa.RSAPublicKey | dsa.DSAPublicKey:
        return key_from_pem(self.public.encode())


class CSR(models.Model):
    key = models.ForeignKey(to=Key, on_delete=models.RESTRICT)

    name = models.CharField(verbose_name="Internal name", max_length=255)
    body = models.TextField(verbose_name="CSR", blank=True)
    params = models.JSONField(verbose_name="Certificate params", blank=True)
    ca = models.BooleanField(verbose_name="CA", default=False)
    path_length = models.SmallIntegerField(
        verbose_name="Path length", null=True, blank=True
    )
    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )

    signed = models.BooleanField(verbose_name="Signed", default=False)

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs) -> None:
        csr_object = make_csr(self.key.private_as_object(), self.params)
        self.body = csr_to_pem(csr_object).decode()
        self.key.used = True
        self.key.save()
        return super().save(*args, **kwargs)

    def as_object(self) -> x509.CertificateSigningRequest:
        return csr_from_pem(self.body.encode())

    @property
    def subject(self):
        return self.as_object().subject.rfc4514_string()


class Certificate(models.Model):
    csr = models.ForeignKey(to=CSR, on_delete=models.RESTRICT)
    parent = models.ForeignKey(
        to="self", on_delete=models.RESTRICT, null=True, blank=True
    )

    body = models.TextField(verbose_name="Certificate")
    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )

    revoked = models.BooleanField(verbose_name="Revoked", default=False)

    def __str__(self) -> str:
        return self.csr.name

    def save(self, *args, **kwargs) -> None:
        if not self.parent:
            cert_object = make_cert(
                ca_cert=self.csr.as_object(),
                ca_key=self.csr.key.private_as_object(),
                csr=self.csr.as_object(),
                data=self.csr.params,
                self_sign=True,
                issuer_dn=self.csr.params.get("issuerDN"),
            )
        else:
            cert_object = make_cert(
                ca_cert=self.parent.as_object(),
                ca_key=self.parent.csr.key.private_as_object(),
                csr=self.csr.as_object(),
                data=self.csr.params,
                self_sign=False,
                issuer_dn=self.csr.params.get("issuerDN"),
            )
        self.body = cert_to_pem(cert_object).decode()
        self.csr.signed = True
        self.csr.save()
        return super().save(*args, **kwargs)

    def as_object(self) -> x509.Certificate:
        return cert_from_pem(self.body.encode())

    @property
    def subject(self):
        return self.csr.subject


# class CRL(models.Model):
#     pass
