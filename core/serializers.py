from django.contrib.auth.models import User, Permission, Group
from rest_framework import serializers

from .models import LogEntry


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


class SystemPermissionSerializer(serializers.ModelSerializer):
    # content_type = serializers.CharField()
    class Meta:
        model = Permission
        fields = ("id", "name", "content_type", "codename")


class SystemGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ("id", "name", "permissions")


class SystemLogEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = LogEntry
        fields = "__all__"
