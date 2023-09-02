from django.db import models

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
