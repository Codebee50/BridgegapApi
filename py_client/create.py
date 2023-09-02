import requests

endpoint = 'http://localhost:8000/create-category/'

data ={
    'category_title': "helo there by"
}

response = requests.post(endpoint, json=data)
print(response.json())
