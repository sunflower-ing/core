# Generated by Django 4.2.7 on 2023-11-20 17:49

from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("ocsp", "0002_alter_requestlog_options_requestlog_result_and_more"),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name="source",
            unique_together={("name", "host", "addr")},
        ),
    ]
