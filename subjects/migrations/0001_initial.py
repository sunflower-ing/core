# Generated by Django 4.2.7 on 2024-03-06 20:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("x509", "0011_remove_csr_slug"),
    ]

    operations = [
        migrations.CreateModel(
            name="Subject",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "type",
                    models.PositiveSmallIntegerField(
                        choices=[(1, "User"), (2, "Service")],
                        default=1,
                        verbose_name="Subject type",
                    ),
                ),
                (
                    "source",
                    models.PositiveSmallIntegerField(
                        choices=[(1, "Keycloak"), (2, "LDAP")],
                        verbose_name="Source type",
                    ),
                ),
                ("source_id", models.CharField(verbose_name="Remote (source) ID")),
                ("enabled", models.BooleanField(default=True, verbose_name="Enabled")),
                ("data", models.JSONField(blank=True, verbose_name="Subject metadata")),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True, verbose_name="Updated at"),
                ),
                (
                    "cert",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        to="x509.certificate",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [models.Index(fields=["source_id"], name="source_id_idx")],
                "unique_together": {("source", "source_id")},
            },
        ),
    ]
