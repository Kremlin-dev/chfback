
from .models import HGuest, Collection, Payment
from hostel.models import Room
from .serializers import CollectionSerializer
from .serializers import UserSerializer
from .views_auth import MyTokenObtainPairView
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate, login as django_login
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
import requests
from django.conf import settings
from django.shortcuts import get_object_or_404
import uuid
import logging
@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    # print(f"Request data: {request.data}")
    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()

        django_login(request, user)
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        response_data = {
            "refresh": str(refresh),
            "access": access_token,
            "user_id": str(user.id),
            "username": user.username,
            "email": user.email,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    user = authenticate(request, username=username, password=password)

    if user is not None:
        django_login(request, user)
        
        # Manually create tokens using the token classes
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'user_id': user.id,
            'email': user.email,
            'username':user.username
        })
    else:
        return Response({'message': 'Invalid username or password'}, status=status.HTTP_401_UNAUTHORIZED)
# ------------------ USER COLLECTIONS CRUD VIEWS -----------------------
@api_view(['GET'])
@permission_classes([IsAuthenticated]) # handled authenticated user
def user_collections(request, user_id):
    user_collections = Collection.objects.filter(user=user_id)
    if user_collections is None:
        return Response({'message': 'User has no collections'}, status=status.HTTP_404_NOT_FOUND)
    serializer = CollectionSerializer(user_collections, many=True, context={'request': request})
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_to_collection(request, user_id):
    print(f"Request data: {request.data}")
    try:
        user = HGuest.objects.get(id=user_id)
    except HGuest.DoesNotExist:
        return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if 'room_id' not in request.data:
        return Response({'message': 'room_id field is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        room = Room.objects.get(room_id=request.data.get('room_id'))
    except Room.DoesNotExist:
        return Response({'message': 'Room not found'}, status=status.HTTP_404_NOT_FOUND)

    collection = Collection.objects.get_or_create(user=user)[0]
    collection.rooms.add(room)

    return Response({'message': 'Room added to collection successfully'}, status=status.HTTP_201_CREATED)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def remove_from_collection(request, user_id):
    print(f"Request data: {request.data}")
    print(f"User id: {user_id}")
    try:
        user = HGuest.objects.get(id=user_id)
    except HGuest.DoesNotExist:
        return Response({'message': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    if 'room_id' not in request.data:
        return Response({'message': 'room_id field is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        room = Room.objects.get(room_id=request.data.get('room_id'))
    except Room.DoesNotExist:
        return Response({'message': 'Room not found'}, status=status.HTTP_404_NOT_FOUND)

    collection = Collection.objects.get(user=user)
    collection.rooms.remove(room)

    return Response({'message': 'Room removed from collection successfully'}, status=status.HTTP_200_OK)



@api_view(['POST'])
def initialize_payment(request, room_id):
    logger = logging.getLogger(__name__) 

    room = get_object_or_404(Room, room_id=room_id)
    user = request.user

    print(room.price, user.email)

    if not user.email:
        return Response({'error': 'User email is required for payment'}, status=status.HTTP_400_BAD_REQUEST)

    amount = room.price
    paystack_amount = int(amount * 100)
    payment_reference = str(uuid.uuid4())

    headers = {
        'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json',
    }
    data = {
        'email': user.email,
        'amount': paystack_amount,
        'reference': payment_reference,
        'callback_url': ''
    }

    response = requests.post('https://api.paystack.co/transaction/initialize', json=data, headers=headers)

    logger.info(f"Paystack response: {response.status_code} - {response.text}")

    if response.status_code == 200:
        payment_data = response.json()
        Payment.objects.create(
            user=user,
            room=room,
            amount=amount,
            reference=payment_reference,
            status='pending'
        )
        
        return Response({
            'authorization_url': payment_data['data']['authorization_url'],
            'reference': payment_reference
        }, status=status.HTTP_200_OK)

    return Response({'error': 'Payment initialization failed'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_payment(request):
    reference = request.query_params.get('reference')
    if not reference:
        return Response({'error': 'Reference not provided'}, status=status.HTTP_400_BAD_REQUEST)

    payment = get_object_or_404(Payment, reference=reference)

    headers = {
        'Authorization': f'Bearer {settings.PAYSTACK_SECRET_KEY}',
        'Content-Type': 'application/json',
    }

    response = requests.get(f'https://api.paystack.co/transaction/verify/{reference}', headers=headers)

    if response.status_code == 200:
        payment_data = response.json()

        if payment_data['data']['status'] == 'success':
            payment.status = 'confirmed'
            payment.save()

            return Response({'message': 'Payment successful'}, status=status.HTTP_200_OK)
        else:
            payment.status = 'failed'
            payment.save()

    return Response({'error': 'Payment verification failed'}, status=status.HTTP_400_BAD_REQUEST)
