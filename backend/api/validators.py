from rest_framework.validators import UniqueValidator
from .models import Category, SubCategory
from rest_framework import serializers
from rest_framework.response import Response

unique_category_title_validator = UniqueValidator(queryset= Category.objects.all(), lookup='iexact', message="The category title already exists")


def unique_cat_title_validator(value):
    query= Category.objects.filter(category_title__iexact = value)
    if query.exists():
        raise serializers.ValidationError(f"{value} is already a category name")
        
    return value

def unique_sub_category(value):
    qs = SubCategory.objects.filter(sub_category_title = value)
    if qs.exists():
        raise serializers.ValidationError(f"{value} is already a sub category title")
  
