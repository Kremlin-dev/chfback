# Generated by Django 4.2.2 on 2023-07-19 16:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hostel', '0003_alter_hostel_available_rooms_room'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='room',
            name='availability',
        ),
        migrations.AddField(
            model_name='room',
            name='number_available',
            field=models.IntegerField(default=1),
        ),
        migrations.AlterField(
            model_name='room',
            name='bedspace',
            field=models.CharField(choices=[('4-in-1', '4 persons in 1 room'), ('3-in-1', '3 persons in 1 room'), ('2-in-1', '2 persons in 1 room'), ('1-in-1', '1 person in 1 room')], max_length=10),
        ),
    ]
