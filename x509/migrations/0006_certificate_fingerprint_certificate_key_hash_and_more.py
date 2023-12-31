# Generated by Django 4.2.6 on 2023-10-24 12:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [("x509", "0005_key_fingerprint")]

    operations = [
        migrations.AddField(
            model_name="certificate",
            name="fingerprint",
            field=models.CharField(
                blank=True,
                max_length=40,
                null=True,
                unique=True,
                verbose_name="Fingerprint",
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="key_hash",
            field=models.CharField(
                blank=True, max_length=40, null=True, verbose_name="Key hash"
            ),
        ),
        migrations.AddField(
            model_name="certificate",
            name="name_hash",
            field=models.CharField(
                blank=True, max_length=40, null=True, verbose_name="Name hash"
            ),
        ),
    ]
