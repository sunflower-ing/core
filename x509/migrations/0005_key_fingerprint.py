# Generated by Django 4.2.6 on 2023-10-23 19:42

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("x509", "0004_alter_certificate_options_alter_csr_options_and_more")
    ]

    operations = [
        migrations.AddField(
            model_name="key",
            name="fingerprint",
            field=models.CharField(
                db_index=True,
                max_length=40,
                null=True,
                unique=True,
                verbose_name="Fingerprint",
            ),
        )
    ]
