from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.contrib.sites.shortcuts import get_current_site
from rest_framework import generics
from .serializers import ProductSerializer, CategorySerializer, SubCategorySerializer
from .models import Category, Product, SubCategory
from rest_framework import status
from django.contrib.auth.models import User, auth
from django.contrib.auth import authenticate, login
import re
from rest_framework.authentication import TokenAuthentication, SessionAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import csrf_exempt
from . import permissions


# Create your views here.

@api_view(['POST'])
def signup(request, *args, **kwargs):
    print('user trying to signup' , request.user.username)
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
            context = {
                'isAdmin': isAdmin,
                'message': 'Account created succesfully',
                'username': username,
                'email': email,
                
            }
            return Response(context, status=status.HTTP_201_CREATED)
    else:
        return Response({'message':'Passwords are not thesame '}, status=status.HTTP_400_BAD_REQUEST)
   
 
@api_view(['POST'])
def login(request, *args, **kwargs):   
    email = request.data.get('email')
    password = request.data.get('password')

    user = auth.authenticate(request, username=email, password=password)

    if user is not None:
        auth.login(request, user)
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
            'userId': request.user.id
        }
        
        }, status= status.HTTP_200_OK)

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