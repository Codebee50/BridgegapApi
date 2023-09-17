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
    path('getuser/', views.getuser, name='getuser'),
    path('contactbridgegap/', views.contactBridgeGap, name='contactbridgegap'),
    path('validateuser', views.validateUser, name='validateuser'),
    path('resendactivationemail', views.resend_activation_email, name='resendactivationemail'),
    path('requestresetpassword/', views.RequestResetPassword, name='requestresetpassword'),
    path('changeuserpassword', views.ChangeUserPassword, name='changeuserpassword'),
    path('deletecategory/<str:pk>', views.DeleteCategory.as_view(), name='deletecategory'),
    path('deletesubcategory/<str:pk>', views.DeleteSubCategory.as_view(), name='deletesubcategory'),
    path('deleteproduct/<str:pk>', views.DeleteProduct.as_view(), name='deleteproduct')
]