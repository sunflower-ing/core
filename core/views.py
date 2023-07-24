from django.contrib.auth.models import Group, Permission, User
from django.http import JsonResponse
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response

from .models import Actions, Modules, log
from .serializers import (
    SystemGroupSerializer,
    SystemPermissionSerializer,
    SystemUserSerializer,
)


def index(request):
    return JsonResponse({"i'm": "ok"})


class SystemUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by("-id")
    serializer_class = SystemUserSerializer
    permission_classes = [permissions.IsAdminUser]

    def create(self, request, *args, **kwargs):
        instance = None
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            if request.data.get("password"):
                serializer.instance.set_password(request.data.get("password"))
                serializer.instance.save()
                instance = serializer.instance

        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.CREATE,
            entity="USER",
            description=f"{instance.pk}",
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        partial = kwargs.pop("partial", False)
        serializer = self.get_serializer(
            instance,
            data=request.data,
            context={"request": request},
            partial=partial,
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            if request.data.get("password"):
                instance.set_password(request.data.get("password"))
                instance.save()

        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.UPDATE,
            entity="USER",
            description=f"{instance.pk}",
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.DESTROY,
            entity="USER",
            description=f"{self.get_object().pk}",
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.RETRIEVE,
            entity="USER",
            description=f"{self.get_object().pk}",
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.LIST,
            entity="USER",
            description="",
        )
        return super().list(request, *args, **kwargs)


class SystemGroupViewSet(viewsets.ModelViewSet):
    queryset = Group.objects.all().order_by("-id")
    serializer_class = SystemGroupSerializer
    permission_classes = [permissions.IsAdminUser]

    def create(self, request, *args, **kwargs):
        instance = None
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            instance = serializer.instance

        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.CREATE,
            entity="GROUP",
            description=f"{instance.pk}",
        )
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.UPDATE,
            entity="GROUP",
            description=f"{self.get_object().pk}",
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.DESTROY,
            entity="GROUP",
            description=f"{self.get_object().pk}",
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.RETRIEVE,
            entity="GROUP",
            description=f"{self.get_object().pk}",
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.LIST,
            entity="GROUP",
            description="",
        )
        return super().list(request, *args, **kwargs)


class SystemPermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all().order_by("-id")
    serializer_class = SystemPermissionSerializer
    permission_classes = [permissions.IsAdminUser]

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SYSTEM,
            action=Actions.LIST,
            entity="PERMISSION",
            description="",
        )
        return super().list(request, *args, **kwargs)
