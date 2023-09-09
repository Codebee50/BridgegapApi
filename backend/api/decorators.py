from functools import wraps
from rest_framework.response import Response

def check_user(function):
    @wraps(function)
    def wrap(request, *args, **kwargs):
        if request.user.username =='':
            return Response({'message': 'user is none'}, status=200)
        else:
            context = {
                'message': f'username: {request.user.username}'
            }
            return Response(context, status=200)
    
    return wrap