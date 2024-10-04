import uuid
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.db import models
from django.conf import settings 



class HUser(AbstractUser):
    """
    Class modlel for All Users
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=127, unique=True)
    phone_number = models.CharField(max_length=10)

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.username


class HManager(HUser):
    """
    Class model for Hostel Manager.
    """
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username}"

    class Meta:
        verbose_name, verbose_name_plural = "Manager", "Managers"


class Collection(models.Model):
    """
    Class model for Collection.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=125)
    user = models.ForeignKey('HGuest', on_delete=models.CASCADE, related_name='collections')
    rooms = models.ManyToManyField('hostel.Room', related_name='collections')

    def __str__(self):
        return f"Collection {self.id} for {self.user.username}"


class HGuest(HUser):
    """
    Class model for Hostel Guest.
    """

    check_in_date = models.DateField(blank=True, null=True)
    check_out_date = models.DateField(blank=True, null=True)
    emergency_contact_name = models.CharField(
        blank=True, null=True, max_length=255)
    emergency_contact_phone = models.CharField(
        blank=True, null=True, max_length=20)
    # collections = models.ManyToManyField('Collection', related_name='collected_by')

    def __str__(self):
        return f"{self.username} - Guest ID: {self.id}"

    class Meta:
        verbose_name, verbose_name_plural = "Guest", "Guests"


class Payment(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    room = models.ForeignKey('hostel.Room', on_delete=models.SET_NULL, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    reference = models.CharField(max_length=200, unique=True)  
    status = models.CharField(max_length=20, default='pending')
    payment_date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.reference} - {self.status}"