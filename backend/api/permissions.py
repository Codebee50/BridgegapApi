from rest_framework import permissions

class CustomIsStaffPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        print('staff status', request.user.is_staff)
        if not request.user.is_staff:
            return False
        return super().has_permission(request, view)