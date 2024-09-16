from django.db import models


class OVPNTemplate(models.Model):
    name = models.CharField(verbose_name="Name", max_length=255)
    body = models.TextField(verbose_name="Template body", blank=True)

    created_at = models.DateTimeField(
        verbose_name="Created at", auto_now_add=True
    )
    updated_at = models.DateTimeField(verbose_name="Updated at", auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.name} ({self.pk})"
