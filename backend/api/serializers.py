from rest_framework import serializers
from .models import Product, Category, SubCategory
from . import validators

class ProductSerializer(serializers.ModelSerializer):
    product_url = serializers.HyperlinkedIdentityField(view_name='product-detail', lookup_field='pk')
    category_title = serializers.SerializerMethodField(read_only=True)
    sub_category_title = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = Product
        fields =[
            'category',
            'sub_category',
            'product_title',
            'product_description',
            'product_image',
            'price',
            'product_url',
            'category_title',
            'sub_category_title',
            'id'
        ]

    def get_category_title(self, obj):
        category= Category.objects.get(pk = obj.category.pk) or None
        return category.category_title

    def get_sub_category_title(self, obj):
        sub_category = SubCategory.objects.get(pk = obj.sub_category.pk) or None
        return sub_category.sub_category_title


class CategorySerializer(serializers.ModelSerializer):
    category_title= serializers.CharField(validators = [validators.unique_cat_title_validator])
    class Meta:
        model = Category
        fields =[
            'category_title',
            'id'
        ]

class SubCategorySerializer(serializers.ModelSerializer):
    # category = serializers.SerializerMethodField(read_only =True)
    sub_category_title = serializers.CharField(validators = [validators.unique_sub_category])
    category_title = serializers.SerializerMethodField(read_only =True)
    class Meta:
        model = SubCategory
        fields =[
            'category',
            'sub_category_title',
            'id',
            'category_title'
        ]
    
    
    def get_category_title(self, obj):
        category= Category.objects.get(pk = obj.category.pk) or None
        return category.category_title

    

  
    
 