# Generated by Django 4.2.2 on 2023-07-19 13:31

from django.db import migrations, models
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Hostel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=64)),
                ('location', models.CharField(max_length=100)),
                ('available_rooms', models.IntegerField()),
                ('description', models.TextField(max_length=1000)),
                ('rating', models.FloatField()),
            ],
        ),
    ]
