from django.urls import path
from . import views

urlpatterns =[ 
    path('', views.GetDetails, name='get_website_details'),
    path('create-category/', views.CreateCategory, name='create-category'),
    path('create-sub-category/', views.CreateSubCategory, name='create-sub-category'),
    path('list-categories/', views.ListCategoryApiVeiw.as_view(), name='list-categories' ),
    path('list-sub-categories/', views.ListSubCategoryApiView.as_view(), name='list-sub-categories'),
    path('create-product/', views.CreateProduct, name='create-product'),
    path('list-products/', views.GetProductsApiView.as_view(), name='list-products'),
    path('product-detail/<int:pk>/', views.ProductDetailApiView.as_view(), name='product-detail'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login, name='login'),
    path('getcurrentuser/', views.getCurrentUser, name='getcurrentuser'),
    path('validate-token/', views.validateToken, name='validatetoken'),
    path('logout/', views.logout, name='logout' ),
    path('edituser/', views.edituser, name='edituser'),
    path('getuser/', views.getuser, name='getuser')
]