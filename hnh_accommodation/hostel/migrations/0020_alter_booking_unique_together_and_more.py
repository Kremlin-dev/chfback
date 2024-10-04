# Generated by Django 5.1 on 2024-10-04 16:52

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("hostel", "0019_booking"),
    ]

    operations = [
        migrations.AlterUniqueTogether(
            name="booking",
            unique_together={("room", "status")},
        ),
        migrations.RemoveField(
            model_name="booking",
            name="check_in_date",
        ),
        migrations.RemoveField(
            model_name="booking",
            name="check_out_date",
        ),
    ]
