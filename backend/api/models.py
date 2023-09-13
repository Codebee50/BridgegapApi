from django.db import models
from django.contrib.auth import get_user_model

# Create your models here.

class Category(models.Model):
    category_title = models.CharField(max_length=100)

class SubCategory(models.Model):
    sub_category_title = models.CharField(max_length=100)
    category = models.ForeignKey(Category, on_delete=models.CASCADE)

   
class Product(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE)
    sub_category = models.ForeignKey(SubCategory, on_delete=models.CASCADE)
    product_title = models.CharField(max_length=100)
    product_description = models.TextField(blank=True, null=True)
    product_image = models.ImageField(upload_to='product_images', default='blank.png')
    price = models.DecimalField(max_digits=15, decimal_places=2, default=0.00)

current_user = get_user_model()
class Profile(models.Model):
    user = models.ForeignKey(current_user, on_delete=models.CASCADE)
    id_user = models.IntegerField(default= -1)
    is_email_verified = models.BooleanField(default=False)
