# Generated by Django 4.2.2 on 2023-07-19 18:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('usermanagement', '0004_alter_hguest_check_in_date_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='hguest',
            name='is_verified',
        ),
        migrations.AddField(
            model_name='hmanager',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
    ]
