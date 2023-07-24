from django.contrib.auth.models import User
from django.db import models


class Modules(models.TextChoices):
    SYSTEM = "system", "System"
    X509 = "x509", "X509"
    OCSP = "ocsp", "OCSP"


class Actions(models.TextChoices):
    RETRIEVE = "GET", "Get one"
    LIST = "GET[]", "Get list"
    CREATE = "POST", "Create"
    UPDATE = "PUT", "Update"
    DESTROY = "DELETE", "Delete"


class LogRecord(models.Model):
    user = models.ForeignKey(
        to=User, verbose_name="User", on_delete=models.DO_NOTHING
    )
    module = models.CharField(
        verbose_name="Module", max_length=12, choices=Modules.choices
    )
    action = models.CharField(
        verbose_name="Action", max_length=12, choices=Actions.choices
    )
    entity = models.CharField(verbose_name="Entity", max_length=32)
    description = models.CharField(verbose_name="Description", max_length=255)
    created_at = models.DateTimeField(
        verbose_name="Created", auto_now_add=True
    )

    def __str__(self) -> str:
        return f"{self.user.username}: {self.module} -> {self.action}"


def log(
    user: User, module: str, action: str, entity: str, description: str
) -> LogRecord:
    return LogRecord.objects.create(
        user=user,
        module=module,
        action=action,
        entity=entity,
        description=description,
    )
