from django.db import models

from x509.models import Certificate

SUBJECT_USER = 1
SUBJECT_SERVICE = 2

SUBJECT_CHOICES = (
    (SUBJECT_USER, "User"),
    (SUBJECT_SERVICE, "Service"),
)

SOURCE_KEYCLOAK = 1
SOURCE_LDAP = 2

SOURCE_CHOICES = ((SOURCE_KEYCLOAK, "Keycloak"), (SOURCE_LDAP, "LDAP"))


class Subject(models.Model):
    type = models.PositiveSmallIntegerField(
        verbose_name="Subject type",
        choices=SUBJECT_CHOICES,
        default=SUBJECT_USER,
    )
    source = models.PositiveSmallIntegerField(
        verbose_name="Source type", choices=SOURCE_CHOICES
    )
    source_id = models.CharField(verbose_name="Remote (source) ID")
    enabled = models.BooleanField(verbose_name="Enabled", default=True)
    data = models.JSONField(
        verbose_name="Subject metadata", blank=True, default=dict
    )
    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )
    updated_at = models.DateTimeField(verbose_name="Updated at", auto_now=True)
    cert = models.ForeignKey(
        to=Certificate, on_delete=models.DO_NOTHING, null=True
    )

    class Meta:
        ordering = ["-created_at"]
        unique_together = ["source", "source_id"]
        indexes = [models.Index(fields=["source_id"], name="source_id_idx")]

    def __str__(self) -> str:
        return f"{self.type} {self.source_id}"
