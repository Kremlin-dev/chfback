# Generated by Django 4.2.2 on 2023-07-19 13:31

from django.db import migrations, models
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('usermanagement', '0002_hguest_hmanager_huser_phone_number_alter_huser_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='hguest',
            name='check_in_date',
            field=models.DateField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='hguest',
            name='check_out_date',
            field=models.DateField(default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='hguest',
            name='emergency_contact_name',
            field=models.CharField(default=123456789, max_length=255),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='hguest',
            name='emergency_contact_phone',
            field=models.CharField(default=123456789, max_length=20),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='hguest',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='hguest',
            name='special_requests',
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='huser',
            name='id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False),
        ),
    ]
