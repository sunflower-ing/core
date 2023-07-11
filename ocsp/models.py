from django.db import models

from x509.models import Certificate


class Source(models.Model):
    name = models.CharField(verbose_name="Source name", max_length=255)
    host = models.CharField(
        verbose_name="Source hostname", max_length=255, blank=True, null=True
    )
    addr = models.GenericIPAddressField(
        verbose_name="Source IP", blank=True, null=True
    )

    def __str__(self) -> str:
        return f"{self.name} ({self.addr})"


class RequestLog(models.Model):
    date = models.DateTimeField(verbose_name="Request date", auto_now_add=True)
    cert = models.ForeignKey(to=Certificate, on_delete=models.DO_NOTHING)
    host = models.CharField(
        verbose_name="Remote hostname", max_length=255, blank=True, null=True
    )
    addr = models.GenericIPAddressField(verbose_name="Remote IP")

    class Meta:
        ordering = ["-date"]

    def __str__(self) -> str:
        return f"{self.date} {self.cert.subject} {self.addr}"
