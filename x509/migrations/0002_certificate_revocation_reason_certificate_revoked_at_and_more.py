# Generated by Django 4.2 on 2023-05-19 07:44

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [("x509", "0001_initial")]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="revocation_reason",
            field=models.CharField(
                blank=True,
                choices=[
                    ("unspecified", "unspecified"),
                    ("keyCompromise", "key_compromise"),
                    ("cACompromise", "ca_compromise"),
                    ("affiliationChanged", "affiliation_changed"),
                    ("superseded", "superseded"),
                    ("cessationOfOperation", "cessation_of_operation"),
                    ("certificateHold", "certificate_hold"),
                    ("privilegeWithdrawn", "privilege_withdrawn"),
                    ("aACompromise", "aa_compromise"),
                    ("removeFromCRL", "remove_from_crl"),
                ],
                max_length=20,
                null=True,
                verbose_name="Revocation reason",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="revoked_at",
            field=models.DateTimeField(
                blank=True, null=True, verbose_name="Revoked at"
            ),
        ),
        migrations.AlterField(
            model_name="certificate",
            name="parent",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.RESTRICT,
                to="x509.certificate",
            ),
        ),
        migrations.CreateModel(
            name="CRL",
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
                ("body", models.TextField(verbose_name="CRL")),
                (
                    "last_update",
                    models.DateTimeField(auto_now=True, verbose_name="Last update"),
                ),
                ("next_update", models.DateTimeField(verbose_name="Next update")),
                (
                    "ca",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.RESTRICT,
                        to="x509.certificate",
                    ),
                ),
            ],
        ),
    ]
