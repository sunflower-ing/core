from django_filters import rest_framework
from rest_framework import permissions, viewsets
from rest_framework.response import Response

from core.models import Actions, Modules, log

from .models import Subject, SUBJECT_USER, SUBJECT_SERVICE
from .serializers import SubjectSerializer


class UserSubjectViewSet(viewsets.ModelViewSet):
    queryset = Subject.objects.filter(type=SUBJECT_USER)
    serializer_class = SubjectSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [rest_framework.DjangoFilterBackend]
    filterset_fields = ["cert"]

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
            module=Modules.SUBJECTS,
            action=Actions.CREATE,
            entity="USER_SUBJECT",
            object_id=instance.pk,
        )
        return Response(SubjectSerializer(instance=instance).data)

    def update(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.UPDATE,
            entity="USER_SUBJECT",
            object_id=self.get_object().pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.DESTROY,
            entity="USER_SUBJECT",
            object_id=self.get_object().pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.RETRIEVE,
            entity="USER_SUBJECT",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.LIST,
            entity="USER_SUBJECT",
        )
        return super().list(request, *args, **kwargs)


class ServiceSubjectViewSet(viewsets.ModelViewSet):
    queryset = Subject.objects.filter(type=SUBJECT_SERVICE)
    serializer_class = SubjectSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [rest_framework.DjangoFilterBackend]
    filterset_fields = ["cert"]

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
            module=Modules.SUBJECTS,
            action=Actions.CREATE,
            entity="SERVICE_SUBJECT",
            object_id=instance.pk,
        )
        return Response(SubjectSerializer(instance=instance).data)

    def update(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.UPDATE,
            entity="SERVICE_SUBJECT",
            object_id=self.get_object().pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.DESTROY,
            entity="SERVICE_SUBJECT",
            object_id=self.get_object().pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.RETRIEVE,
            entity="SERVICE_SUBJECT",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.SUBJECTS,
            action=Actions.LIST,
            entity="SERVICE_SUBJECT",
        )
        return super().list(request, *args, **kwargs)
