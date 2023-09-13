from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import generics
from .serializers import ProductSerializer, CategorySerializer, SubCategorySerializer
from .models import Category, Product, SubCategory, Profile
from rest_framework import status
from django.contrib.auth.models import User, auth
from django.contrib.auth import authenticate, login
import re
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from . import permissions
from bridge import settings
from django.core.mail import send_mail, EmailMultiAlternatives
from django.utils.encoding import force_bytes, force_str as force_text, DjangoUnicodeDecodeError
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import generate_token
from django.utils.html import strip_tags
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Create your views here.
@api_view(['POST'])
def signup(request, *args, **kwargs):
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    confirm_passowrd = request.data.get('confirm_password')

    parts = username.split('===admin')
    if len(parts) >1:
        username = parts[0]
        isAdmin = True
    else:
        isAdmin = False

    
    if password == confirm_passowrd:
        if User.objects.filter(username= username).exists():
            return Response({'message': f'The username {username} already exists'},status=status.HTTP_400_BAD_REQUEST)
        elif User.objects.filter(email= email):
            return Response({'message': 'Email aready exists'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_staff= isAdmin
            user.save()

            user_profile = Profile.objects.create(user=user, id_user=user.id)

            #send a verification email
            sendActivationEmail(request=request, user=user_profile)
            # context = {
            #     'isAdmin': isAdmin,
            #     'message': 'Account created succesfully',
            #     'username': username,
            #     'email': email,
            # }
            # return Response(context, status=status.HTTP_201_CREATED)

            context = {
                'message': f'An email has been sent to {user.email}, click on the link in the email to verify your email address',
                'username': user.username,
                'email': user.email
            }
    
            return Response(context, status=status.HTTP_200_OK)
    else:
        return Response({'message':'Passwords are not the same '}, status=status.HTTP_400_BAD_REQUEST)
   
def sendActivationEmail(request, user):
    email_subject = 'Verify your account'
    if settings.DEBUG:
        current_site = settings.DOMAIN_SITE
    else:
        current_site = get_current_site(request=request)


    email_body = render_to_string('activate.html', {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.user.id)),
        'token': generate_token.make_token(user)
    })

    text_content = strip_tags(email_body)
    sender = 'Bridgegapclothing <' + str(settings.EMAIL_HOST_USER) + '>' 
    email= EmailMultiAlternatives(
        email_subject,
        text_content,
        sender,
        [user.user.email]
    )
    email.attach_alternative(email_body, 'text/html')
    email.send()

@api_view(['POST'])
def RequestResetPassword(request, *args, **kwargs):
    user_email = request.data.get('email')

    user = User.objects.filter(email = user_email)
    try: 
        user = User.objects.get(email=user_email)
    except Exception as e:
        user = None
    if user is not None:
        user_profile = Profile.objects.get(id_user = user.id)
        if settings.DEBUG:
            current_site = settings.DOMAIN_SITE
        else:
            current_site = get_current_site(request=request)
        email_subject = '[Bridgegapclothing] Reset your password'

        email_body = render_to_string('reset-password.html', {
            'user': user_profile,
            'domain': current_site,
            'uid': urlsafe_base64_encode(force_bytes(user_profile.user.id)),
            'token': PasswordResetTokenGenerator().make_token(user)
        })

        text_content = strip_tags(email_body)
        sender = 'Bridgegap Clothing <' + str(settings.EMAIL_HOST_USER) + '>' 
        email = EmailMultiAlternatives(
                email_subject,
                text_content,
                sender,
                [user_profile.user.email] 
            )
        email.attach_alternative(email_body, 'text/html')
        email.content_subtype = 'html'
        email.send()
        return Response({'message': f'Instructions on how to reset your password has been sent to {user_email}'}, status= status.HTTP_200_OK)
    else:
        return Response({'message': f'{user_email} was not found in our records, please ensure that you have previously signed up with this email'}, status= status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def ChangeUserPassword(request, *args, **kwargs):
    uidb64 = request.query_params.get('uidb64')
    token = request.query_params.get('token')

    password_one = request.data.get('password-one')
    password_two = request.data.get('password-two')

    if password_one != password_two:
        return Response({'message': 'Passwords do not match'}, status= status.HTTP_400_BAD_REQUEST)
    else:
        try:
            #decode this and give us the user id
            #its returns a byte so we have to turn it to string using force text
            user_id = force_text(urlsafe_base64_decode(uidb64))
            if User.objects.filter(id = user_id).exists():
                user = User.objects.get(id = user_id)
                token_generator = PasswordResetTokenGenerator()
                if token_generator.check_token(user=user, token=token):
                    
                    user.set_password(password_one)
                    user.save()
                    return Response({'message': 'Password has been changed succesfully'}, status= status.HTTP_200_OK)
                else:
                    return Response({'message': 'Password reset link is invalid or expired, please reqeust a new one'}, status= status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'message': 'FATAL: An error occured'}, status=status.HTTP_400_BAD_REQUEST)
        except DjangoUnicodeDecodeError as identifier:
            return Response({'message': 'FATAL: An error occured'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



@api_view(['POST'])
def resend_activation_email(request, *args, **kwargs):
    email = request.query_params.get('email')
    try:
        user = User.objects.get(email= email)
    except Exception as e:
        user = None
    
    if user is not None:
        user_profile = Profile.objects.get(id_user = user.id)
        if user_profile.is_email_verified:
            return Response({'message': 'Your account is already verified, you can now login'}, status= status.HTTP_200_OK)
        else:
            if settings.DEBUG:
                current_site = settings.DOMAIN_SITE
            else:
                current_site = get_current_site(request=request)

            email_body = render_to_string('activate.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user_profile.user.id)),
                'token': generate_token.make_token(user_profile)
            })

            email_subject = 'Verify your account'
            text_content = strip_tags(email_body)
            sender = 'Bridgegapclothing <' + str(settings.EMAIL_HOST_USER) + '>' 
            email= EmailMultiAlternatives(
                email_subject,
                text_content,
                sender,
                [user_profile.user.email]
            )
            email.attach_alternative(email_body, 'text/html')
            email.send()

            return Response({'message': f'Confirmation email has been resent to {user_profile.user.email}'})        
    else:
        return Response({'message': f'{email} could not be located in our records, Ensure you are signed up using this email'}, status= status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def validateUser(request, *args, **kwargs):
    encoded_uid = request.query_params.get('uidb64')
    token = request.query_params.get('token')

    try:
        uid = force_text(urlsafe_base64_decode(encoded_uid))
        user_profile = Profile.objects.get(id_user=uid)
    except Exception as e:
        user_profile = None
    
    if user_profile and generate_token.check_token(user_profile, token):
        user_profile.is_email_verified = True
        user_profile.save()
        return Response({'message': 'Account verification complete'}, status=status.HTTP_200_OK)
    
    return Response({'message': 'Account verification failed'}, status=status.HTTP_400_BAD_REQUEST)

        
@api_view(['POST'])
def login(request, *args, **kwargs):   
    email = request.data.get('email')
    password = request.data.get('password')

    user = auth.authenticate(request, username=email, password=password)
    try:
        user_profile = Profile.objects.get(id_user=user.id)
    except Exception as e:
        user_profile = None
    
    if user is not None:
        if user_profile is not None and user_profile.is_email_verified:
            try:
                old_token = Token.objects.get(user=user)
                old_token.delete()
            except Token.DoesNotExist:
                pass

            token, created = Token.objects.get_or_create(user=user)
            
            context ={
                'message': 'Login successfull',
                'is_staff': user.is_staff,
                'token': token.key
            }
            return Response(context, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Your email is not verified, please verify your email before proceeding'}, status=  status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'message': 'Invalid credentials'}, status= status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def logout(request):
    if request.user.username != '':
        username = request.user.username
        auth.logout(request)
        return Response({'message': 'loogged out user succesfully', 'user': username})
    else:
        return Response({'message': 'user is none'})

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def validateToken(request):

    return Response({'message': 'Token is valid'}, status= status.HTTP_200_OK)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def getCurrentUser(request, *args, **kwargs):
    return Response({
        'message': 'user found',
        'user': {
            'username': request.user.username,
            'is_staff': request.user.is_staff,
            'userId': request.user.id,
            'email': request.user.email
        }
        
        }, status= status.HTTP_200_OK)

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def edituser(request, *args, **kwargs):
    print('pagahga')
    new_username = request.data.get('username')
    print('the new username is ', new_username)
    if not User.objects.filter(username= new_username):
        try:
            user = User.objects.get(id = request.user.id)
        except Exception as e:
            user = None

        if(user):
            user.username = new_username
            user.save()
            return Response({
                'message': 'User updated succesfully',
                'username': user.username
            }, status= status.HTTP_200_OK)
        else:
            return Response({
                'message': 'User does not exist'
            }, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({
            'message': f"A user with the name {new_username} already exists"
        })
    

@api_view(['POST', 'GET'])
def getuser(request):
    return Response({
        'message': 'user found',
        'user': {
            'username': request.user.username,
            'userid': request.user.id
        }
    }, status= status.HTTP_200_OK)


"""this view gets creates a category in the database if te category name does not already exist"""
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, permissions.CustomIsStaffPermission])
def CreateCategory(request, *args, **kwargs):
    context = {}
    category_title = request.data.get('category_title')
    if category_title is not None:
        #checking if category title already exists
        if Category.objects.filter(category_title = category_title).exists():
            context = {
                'message': f"a category with the name {category_title} already exists",
                'status': status.HTTP_400_BAD_REQUEST
            }
            return Response(context, status= status.HTTP_400_BAD_REQUEST)

        serializer = CategorySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            context = {
                'message': f"category {category_title} created succsefully",
                 'status': status.HTTP_201_CREATED,
                'content': serializer.data
                
            }
            return Response(context, status=status.HTTP_201_CREATED)
    else:
        context = {
            'message': 'category_title must not be empty'
        }

        return Response(context, status=status.HTTP_400_BAD_REQUEST)
    
@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, permissions.CustomIsStaffPermission])
def CreateSubCategory(request, *args, **kwargs):
    context = {}
    category_title = request.data.get('category_title')
    sub_category_title = request.data.get('sub_category_title')

    if category_title is not None:
        category = Category.objects.filter(category_title = category_title)
        
        if category.exists():
            category_object = Category.objects.get(category_title = category_title)
            if not SubCategory.objects.filter(category= category_object.pk, sub_category_title = sub_category_title).exists():
                print(type(sub_category_title))
                data = {
                    "sub_category_title": sub_category_title,
                    'category': category_object.pk
                }
                serializer = SubCategorySerializer(data=data)
                
                if serializer.is_valid():
                    serializer.save()
                    context = {
                        'message': f"a subcategory '{sub_category_title}' has been created under the category '{category_title}' successfully",
                        'status': status.HTTP_201_CREATED,
                        'content': serializer.data
                    }
                    return Response(context, status= status.HTTP_201_CREATED)
                else:
                    m_error = serializer.errors.get('sub_category_title', [])
                    return Response({'message': m_error}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'message': f"A sub category with the title '{sub_category_title}' already exists under the category '{category_title}' "}, status= status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': f'There is no category with the title {category_title}'}, status= status.HTTP_400_BAD_REQUEST)

class CreateProductApiVeiw(generics.CreateAPIView):
    serializer_class = ProductSerializer

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated, permissions.CustomIsStaffPermission])
def CreateProduct(request, *args, **kwargs):
    category_title = request.data.get('category_title')
    sub_category_title = request.data.get('sub_category_title')
    product_title = request.data.get('product_title')
    product_description = request.data.get('product_description')
    price = request.data.get('price')
    product_image = request.FILES['product_image']

    if Category.objects.filter(category_title = category_title).exists():
        if SubCategory.objects.filter(sub_category_title = sub_category_title).exists():
            category = Category.objects.get(category_title = category_title).pk
            sub_category = SubCategory.objects.get(sub_category_title = sub_category_title).pk

            data = {
                'category': category,
                'sub_category': sub_category,
                'product_title': product_title,
                'product_description': product_description,
                'price': price,
                'product_image': product_image
            }
            context = {}
            serializer = ProductSerializer(data= data, context={'request': request})
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                context = {
                    'message': 'product created succesfully',
                    'status': status.HTTP_201_CREATED,
                    'content': serializer.data
                }

                return Response(context, status=status.HTTP_201_CREATED)
            context = {
                'message': 'invalid http request format'
            }
            return Response(context, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': f"sub category {sub_category_title} does not exist"})
    else:
        return Response({'message': f"category {category_title} does not exist"}, status=status.HTTP_400_BAD_REQUEST)
    
class GetProductsApiView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer

class ProductDetailApiView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer

class ListCategoryApiVeiw(generics.ListAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer

class ListSubCategoryApiView(generics.ListAPIView):
    queryset = SubCategory.objects.all()
    serializer_class = SubCategorySerializer

@api_view(['GET', 'POST'])
def GetDetails(request, *args, **kwargs):
    current_site =get_current_site(request)
    context = {
        'domain': str(current_site),
        'site_name': 'Bridge Gap Clothing'
    }
    return Response(context)

@api_view(['POST'])
def contactBridgeGap(request, *args, **kwargs):
    print('seding email..')
    email = request.data.get('email')
    subject = request.data.get('subject')
    message = request.data.get('message')

    sender = 'Bridgegapclothing <' + str(settings.EMAIL_HOST_USER) + '>' 
    send_mail(subject, message, sender, ['codebee345@outlook.com', 'onuhudoudo@gmail.com'],fail_silently=False)
    return Response({'message': 'email sent succesfully'})



