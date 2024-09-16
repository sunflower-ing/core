from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from django.conf import settings
from django.db import models
from django.utils import timezone

from utils.crypto import (
    REVOCATION_REASONS,
    cert_from_pem,
    cert_to_pem,
    crl_from_pem,
    crl_to_der,
    crl_to_pem,
    csr_from_pem,
    csr_to_pem,
    get_cert_fingerprint,
    get_cert_subject_fingerprint,
    get_key_fingerprint,
    key_from_pem,
    key_to_pem,
    make_cert,
    make_crl,
    make_csr,
    make_keys,
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

REVOCATION_CHOICES = tuple(
    (value, key) for (key, value) in REVOCATION_REASONS.items()
)


def get_hosts():
    return list(filter(lambda h: h != "*", settings.ALLOWED_HOSTS))


class Key(models.Model):
    name = models.CharField(verbose_name="Internal name", max_length=255)
    private = models.TextField(
        verbose_name="Private part", blank=True, null=True
    )
    public = models.TextField(verbose_name="Public part", blank=True)
    fingerprint = models.CharField(
        verbose_name="Fingerprint",
        max_length=40,
        unique=True,
        db_index=True,
        null=True,
    )
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

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} {self.algo}({self.length})"

    def save(self, *args, **kwargs) -> None:
        if self._state.adding is True:
            if not self.public:
                if self.private:  # On import
                    private_key = self.private_as_object()
                    public_key = private_key.public_key()
                else:  # On API create
                    private_key, public_key = make_keys(self.algo, self.length)
                self.private = key_to_pem(private_key, private=True).decode()
                self.public = key_to_pem(public_key).decode()
            else:  # On certificate import
                public_key = self.public_as_object()
            self.fingerprint = get_key_fingerprint(public_key).decode()
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
    key_usage = models.JSONField(verbose_name="Key Usage", blank=True)
    extended_key_usage = models.JSONField(
        verbose_name="Extended Key Usage", blank=True
    )
    ca = models.BooleanField(verbose_name="CA", default=False)
    path_length = models.SmallIntegerField(
        verbose_name="Path length", null=True, blank=True
    )
    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )

    signed = models.BooleanField(verbose_name="Signed", default=False)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs) -> None:
        data: dict = self.params
        data.update({"ca": self.ca, "path_length": self.path_length})

        csr_object = make_csr(self.key.private_as_object(), data)
        self.body = csr_to_pem(csr_object).decode()
        self.key.used = True
        self.key.save()
        return super().save(*args, **kwargs)

    def as_object(self) -> x509.CertificateSigningRequest:
        return csr_from_pem(self.body.encode())

    @property
    def subject(self) -> str:
        return self.as_object().subject.rfc4514_string()


class Certificate(models.Model):
    csr = models.ForeignKey(to=CSR, on_delete=models.RESTRICT, null=True)
    key = models.ForeignKey(to=Key, on_delete=models.RESTRICT, null=True)
    parent = models.ForeignKey(
        to="self", on_delete=models.RESTRICT, null=True, blank=True
    )
    sn = models.BigIntegerField(
        verbose_name="Serial number", null=True, blank=True
    )
    body = models.TextField(verbose_name="Certificate", blank=True)
    fingerprint = models.CharField(
        verbose_name="Fingerprint",
        max_length=40,
        unique=True,
        null=True,
        blank=True,
    )
    name_hash = models.CharField(
        verbose_name="Name hash", max_length=40, null=True, blank=True
    )
    key_hash = models.CharField(
        verbose_name="Key hash", max_length=40, null=True, blank=True
    )
    imported = models.BooleanField(
        verbose_name="Imported", default=False, blank=True
    )
    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )

    revoked = models.BooleanField(verbose_name="Revoked", default=False)
    revocation_reason = models.CharField(
        verbose_name="Revocation reason",
        max_length=20,
        choices=REVOCATION_CHOICES,
        null=True,
        blank=True,
    )
    revoked_at = models.DateTimeField(
        verbose_name="Revoked at", null=True, blank=True
    )

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return self.name

    def save(self, *args, **kwargs) -> None:
        if self._state.adding is True:
            if self.csr:
                if not self.parent:
                    cert_object = make_cert(
                        ca_cert=self.csr.as_object(),
                        ca_key=self.csr.key.private_as_object(),
                        csr=self.csr.as_object(),
                        key=self.csr.key.private_as_object(),
                        data=self.csr.params,
                        ku=self.csr.key_usage,
                        eku=self.csr.extended_key_usage,
                        self_sign=True,
                        issuer_dn=self.csr.params.get("issuerDN"),
                    )
                else:
                    cert_object = make_cert(
                        ca_cert=self.parent.as_object(),
                        ca_key=self.parent.csr.key.private_as_object(),
                        csr=self.csr.as_object(),
                        key=self.csr.key.private_as_object(),
                        data=self.csr.params,
                        ku=self.csr.key_usage,
                        eku=self.csr.extended_key_usage,
                        self_sign=False,
                        issuer_dn=self.csr.params.get("issuerDN"),
                    )
                self.body = cert_to_pem(cert_object).decode()
                self.key = self.csr.key
                self.key_hash = self.csr.key.fingerprint
                self.csr.signed = True
                self.csr.save()
            else:  # On import
                cert_object = cert_from_pem(self.body.encode())

            self.sn = cert_object.serial_number
            self.fingerprint = get_cert_fingerprint(cert_object).decode()
            self.name_hash = get_cert_subject_fingerprint(cert_object).decode()

        return super().save(*args, **kwargs)

    def revoke(self, reason: str = None) -> None:
        self.revoked = True
        self.revoked_at = timezone.now()
        self.revocation_reason = (
            reason if reason else REVOCATION_REASONS["unspecified"]
        )
        self.save()

        if self.parent:
            crl = CRL.objects.filter(ca=self.parent).first()
            crl.save()

    def as_object(self) -> x509.Certificate:
        return cert_from_pem(self.body.encode())

    @property
    def name(self) -> str:
        return self.csr.name if self.csr else f"(imported) SN: {self.sn}"

    @property
    def subject(self) -> str:
        return self.as_object().subject.rfc4514_string()

    @property
    def expires_at(self) -> datetime:
        return self.as_object().not_valid_after_utc

    @property
    def cn(self) -> str | None:
        for attr in self.as_object().subject:
            if attr.rfc4514_attribute_name == "CN":
                return str(attr.value)
        return None

    @property
    def is_ca(self) -> bool:
        if self.csr:
            return self.csr.ca
        for ext in self.as_object().extensions:
            if ext.value.oid._name == "basicConstraints":
                return ext.value.ca
        return False

    @property
    def num_signed(self) -> int:
        return Certificate.objects.filter(parent=self).count()


class CRL(models.Model):
    ca = models.ForeignKey(to=Certificate, on_delete=models.RESTRICT)
    body = models.TextField(verbose_name="CRL")

    last_update = models.DateTimeField(
        verbose_name="Last update", auto_now=True
    )
    next_update = models.DateTimeField(verbose_name="Next update")

    def __str__(self) -> str:
        return str(self.ca)

    def save(self, *args, **kwargs) -> None:
        if self._state.adding is True:
            crl_object = make_crl(
                self.ca.as_object(), self.ca.key.private_as_object()
            )

        else:
            revoked_certs = []
            for item in Certificate.objects.filter(
                parent=self.ca, revoked=True
            ):
                revoked_certs.append(
                    (item.as_object(), item.revocation_reason, item.revoked_at)
                )

            crl_object = make_crl(
                self.ca.as_object(),
                self.ca.key.private_as_object(),
                revoked_certs,
            )

        self.body = crl_to_pem(crl_object).decode()
        self.next_update = timezone.now() + timezone.timedelta(
            1, 0, 0  # TODO: move next_update delta to config
        )

        return super().save(*args, **kwargs)

    def as_object(self) -> x509.CertificateRevocationList:
        return crl_from_pem(self.body.encode())

    def as_pem(self) -> str:
        if self.next_update <= timezone.now():
            self.save()
        return self.body

    def as_der(self) -> bytes:
        if self.next_update <= timezone.now():
            self.save()
        return crl_to_der(self.as_object())
