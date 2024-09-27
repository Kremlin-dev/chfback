# Generated by Django 4.2.2 on 2023-07-18 17:29

from django.conf import settings
import django.contrib.auth.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('usermanagement', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='HGuest',
            fields=[
                ('huser_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            bases=('usermanagement.huser',),
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='HManager',
            fields=[
                ('huser_ptr', models.OneToOneField(auto_created=True, on_delete=django.db.models.deletion.CASCADE, parent_link=True, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            bases=('usermanagement.huser',),
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.AddField(
            model_name='huser',
            name='phone_number',
            field=models.CharField(default=123456, max_length=10),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name='huser',
            name='id',
            field=models.UUIDField(primary_key=True, serialize=False),
        ),
    ]
