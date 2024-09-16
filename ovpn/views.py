# from django_filters import rest_framework
from rest_framework import permissions, viewsets
from rest_framework.response import Response

from core.models import Actions, Modules, log

from .models import OVPNTemplate
from .serializers import OVPNTemplateSerializer


class OVPNTemplateViewSet(viewsets.ModelViewSet):
    queryset = OVPNTemplate.objects.all()
    serializer_class = OVPNTemplateSerializer
    permission_classes = [permissions.IsAuthenticated]
    # filter_backends = [rest_framework.DjangoFilterBackend]
    # filterset_fields = ["cert"]

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
            module=Modules.OVPN,
            action=Actions.CREATE,
            entity="OVPN_TEMPLATE",
            object_id=instance.pk,
        )
        return Response(OVPNTemplateSerializer(instance=instance).data)

    def update(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.OVPN,
            action=Actions.UPDATE,
            entity="OVPN_TEMPLATE",
            object_id=self.get_object().pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.OVPN,
            action=Actions.DESTROY,
            entity="OVPN_TEMPLATE",
            object_id=self.get_object().pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.OVPN,
            action=Actions.RETRIEVE,
            entity="OVPN_TEMPLATE",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.OVPN,
            action=Actions.LIST,
            entity="OVPN_TEMPLATE",
        )
        return super().list(request, *args, **kwargs)
