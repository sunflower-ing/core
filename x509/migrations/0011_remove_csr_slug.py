# Generated by Django 4.2.7 on 2024-01-10 15:06

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("x509", "0010_csr_extended_key_usage_csr_key_usage"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="csr",
            name="slug",
        ),
    ]
