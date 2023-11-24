from django.db import models

from x509.models import Certificate

OCSP_RESULT_OK = 1
OCSP_RESULT_REVOKED = 2
OCSP_RESULT_UNKNOWN = 3
OCSP_RESULT_ERROR = 4
OCSP_RESULT_CHOICES = (
    (OCSP_RESULT_OK, "OK"),
    (OCSP_RESULT_REVOKED, "REVOKED"),
    (OCSP_RESULT_UNKNOWN, "UNKNOWN CERT"),
    (OCSP_RESULT_ERROR, "MALFORMED REQUEST"),
)


class Source(models.Model):
    name = models.CharField(verbose_name="Source name", max_length=255)
    host = models.CharField(
        verbose_name="Source hostname", max_length=255, blank=True, null=True
    )
    addr = models.GenericIPAddressField(
        verbose_name="Source IP", blank=True, null=True
    )

    class Meta:
        unique_together = ["name", "host", "addr"]

    def __str__(self) -> str:
        return f"{self.name} ({self.addr})"


class RequestLog(models.Model):
    date = models.DateTimeField(verbose_name="Request date", auto_now_add=True)
    cert = models.ForeignKey(
        to=Certificate, on_delete=models.DO_NOTHING, null=True
    )
    host = models.CharField(
        verbose_name="Remote hostname", max_length=255, blank=True, null=True
    )
    addr = models.GenericIPAddressField(verbose_name="Remote IP")
    result = models.IntegerField(
        verbose_name="Request result",
        default=OCSP_RESULT_ERROR,
        choices=OCSP_RESULT_CHOICES,
        null=True,
    )

    class Meta:
        ordering = ["-date"]

    def __str__(self) -> str:
        return f"{self.date} {self.cert.subject} {self.addr}"

    def result_display(self) -> str:
        return self.get_result_display()
