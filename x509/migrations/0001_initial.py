# Generated by Django 4.2 on 2023-05-04 07:45

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Key",
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
                    "name",
                    models.CharField(max_length=255, verbose_name="Internal name"),
                ),
                ("private", models.TextField(blank=True, verbose_name="Private part")),
                ("public", models.TextField(blank=True, verbose_name="Public part")),
                (
                    "algo",
                    models.CharField(
                        choices=[("RSA", "RSA"), ("DSA", "DSA")],
                        default="RSA",
                        max_length=7,
                        verbose_name="Algorithm",
                    ),
                ),
                (
                    "length",
                    models.IntegerField(
                        choices=[
                            (1024, "1024"),
                            (2048, "2048"),
                            (3072, "3072"),
                            (4096, "4096"),
                            (8192, "8192"),
                        ],
                        default=4096,
                        null=True,
                        verbose_name="Key length",
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                ("used", models.BooleanField(default=False, verbose_name="Used")),
            ],
        ),
        migrations.CreateModel(
            name="CSR",
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
                    "name",
                    models.CharField(max_length=255, verbose_name="Internal name"),
                ),
                ("body", models.TextField(blank=True, verbose_name="CSR")),
                (
                    "params",
                    models.JSONField(blank=True, verbose_name="Certificate params"),
                ),
                ("ca", models.BooleanField(default=False, verbose_name="CA")),
                (
                    "path_length",
                    models.SmallIntegerField(
                        blank=True, null=True, verbose_name="Path length"
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                ("signed", models.BooleanField(default=False, verbose_name="Signed")),
                (
                    "key",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.RESTRICT, to="x509.key"
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Certificate",
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
                ("body", models.TextField(verbose_name="Certificate")),
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                ("revoked", models.BooleanField(default=False, verbose_name="Revoked")),
                (
                    "csr",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.RESTRICT, to="x509.csr"
                    ),
                ),
                (
                    "parent",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.RESTRICT,
                        to="x509.certificate",
                    ),
                ),
            ],
        ),
    ]
