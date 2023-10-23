# Generated by Django 4.2.3 on 2023-07-11 03:17

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("x509", "0004_alter_certificate_options_alter_csr_options_and_more")
    ]

    operations = [
        migrations.CreateModel(
            name="Source",
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
                ("name", models.CharField(max_length=255, verbose_name="Source name")),
                (
                    "host",
                    models.CharField(
                        blank=True,
                        max_length=255,
                        null=True,
                        verbose_name="Source hostname",
                    ),
                ),
                (
                    "addr",
                    models.GenericIPAddressField(
                        blank=True, null=True, verbose_name="Source IP"
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="RequestLog",
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
                    "date",
                    models.DateTimeField(
                        auto_now_add=True, verbose_name="Request date"
                    ),
                ),
                (
                    "host",
                    models.CharField(
                        blank=True,
                        max_length=255,
                        null=True,
                        verbose_name="Remote hostname",
                    ),
                ),
                ("addr", models.GenericIPAddressField(verbose_name="Remote IP")),
                (
                    "cert",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        to="x509.certificate",
                    ),
                ),
            ],
        ),
    ]