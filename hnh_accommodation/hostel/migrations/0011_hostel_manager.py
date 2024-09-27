# Generated by Django 4.2.2 on 2023-07-19 18:19

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('usermanagement', '0005_remove_hguest_is_verified_hmanager_is_verified'),
        ('hostel', '0010_alter_room_room_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='hostel',
            name='manager',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='hostels_managed', to='usermanagement.hmanager'),
        ),
    ]
