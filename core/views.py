from django.contrib.auth.models import User
from django.http import JsonResponse
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response

from .serializers import SystemUserSerializer


def index(request):
    return JsonResponse({"i'm": "ok"})


class SystemUserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by("-id")
    serializer_class = SystemUserSerializer
    permission_classes = [permissions.IsAdminUser]

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        partial = kwargs.pop('partial', False)
        serializer = self.get_serializer(
            instance,
            data=request.data,
            context={'request': request},
            partial=partial,
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_update(serializer)
            if request.data.get("password"):
                instance.set_password(request.data.get("password"))
                instance.save()
        return Response(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            if request.data.get("password"):
                serializer.instance.set_password(request.data.get("password"))
                serializer.instance.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
