from django.contrib.auth.models import User
from rest_framework import serializers


class SystemUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "password",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "is_staff",
            "is_superuser",
            "last_login",
            "groups",
        )
        extra_kwargs = {"password": {"write_only": True, "required": False}}
