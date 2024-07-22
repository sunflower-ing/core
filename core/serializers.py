from django.contrib.auth.models import Group, Permission, User
from rest_framework import serializers

from .models import LogEntry


class SystemPermissionSerializer(serializers.ModelSerializer):
    # content_type = serializers.CharField()
    class Meta:
        model = Permission
        fields = ("id", "name", "content_type", "codename")


class SystemGroupSerializer(serializers.ModelSerializer):
    permissions = SystemPermissionSerializer(many=True)

    class Meta:
        model = Group
        fields = ("id", "name", "permissions")


class SystemGroupCreateSerializer(SystemGroupSerializer):
    permissions = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Permission.objects.all()
    )


class SystemGroupUpdateSerializer(SystemGroupCreateSerializer):
    pass


class SystemUserSimpleSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
        )


class SystemUserSerializer(serializers.ModelSerializer):
    groups = SystemGroupSerializer(many=True)

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


class SystemUserCreateSerializer(SystemUserSerializer):
    groups = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Group.objects.all()
    )


class SystemUserUpdateSerializer(SystemUserSerializer):
    groups = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Group.objects.all()
    )

    class Meta:
        model = User
        fields = (
            "username",
            "password",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "is_staff",
            "is_superuser",
            "groups",
        )
        extra_kwargs = {
            "username": {"required": False},
            "password": {"write_only": True, "required": False},
        }


class SystemLogEntrySerializer(serializers.ModelSerializer):
    user = SystemUserSimpleSerializer()

    class Meta:
        model = LogEntry
        fields = "__all__"
