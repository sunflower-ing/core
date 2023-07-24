import uuid

from django.http import HttpResponse
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response

from core.models import Actions, Modules, log

from .models import CRL, CSR, Certificate, Key
from .serializers import CertificateSerialiser, CSRSerializer, KeySerializer


class KeyViewSet(viewsets.ModelViewSet):
    queryset = Key.objects.all()
    serializer_class = KeySerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        instance = None
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if not serializer.initial_data.get("name"):
            serializer.initial_data["name"] = str(uuid.uuid4())
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            instance = serializer.instance

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.CREATE,
            entity="KEY",
            object_id=instance.pk,
        )
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.used:
            return Response(
                data={"detail": "Method not allowed for Key in use"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.UPDATE,
            entity="KEY",
            object_id=instance.pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.used:
            return Response(
                data={"detail": "Method not allowed for Key in use"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.DESTROY,
            entity="KEY",
            object_id=instance.pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.RETRIEVE,
            entity="KEY",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.LIST,
            entity="KEY",
        )
        return super().list(request, *args, **kwargs)


class CSRViewSet(viewsets.ModelViewSet):
    queryset = CSR.objects.all()
    serializer_class = CSRSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        instance = None
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if not serializer.initial_data.get("key"):
            key = Key.objects.create(name=str(uuid.uuid4()))
            serializer.initial_data["key"] = key.pk
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            instance = serializer.instance

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.CREATE,
            entity="CSR",
            object_id=instance.pk,
        )
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.signed:
            return Response(
                data={"detail": "Method not allowed for signed CSR"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.UPDATE,
            entity="CSR",
            object_id=instance.pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.signed:
            return Response(
                data={"detail": "Method not allowed for signed CSR"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        else:
            instance.key.used = False
            instance.key.save()  # Free the Key for later use

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.DESTROY,
            entity="CSR",
            object_id=instance.pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.RETRIEVE,
            entity="CSR",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.LIST,
            entity="CSR",
        )
        return super().list(request, *args, **kwargs)


class CertificateViewSet(viewsets.ModelViewSet):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerialiser
    permission_classes = [permissions.IsAuthenticated]

    http_method_names = ["get", "post", "put"]

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        if serializer.is_valid():
            instance = serializer.save()
            if instance.csr.ca:
                crl = CRL(ca=instance)
                crl.save()

            log(
                user=request.user,
                module=Modules.X509,
                action=Actions.CREATE,
                entity="CERTIFICATE",
                object_id=instance.pk,
            )
            return Response(
                data=serializer.data, status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                data=serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.revoked:
            return Response(
                data={"detail": "Certificate already revoked"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # TODO: check only revoked & revocation_reason fields are changed
        if not request.data.get("revoked"):
            return Response(
                data={"detail": "Method can only be used for revocation"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instance.revoke(request.data.get("reason"))

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.UPDATE,
            entity="CERTIFICATE",
            object_id=instance.pk,
        )
        return Response(data=request.data, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.RETRIEVE,
            entity="CERTIFICATE",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.LIST,
            entity="CERTIFICATE",
        )
        return super().list(request, *args, **kwargs)


def crl_view(request, ca_slug, format: str = "crl"):
    crl = CRL.objects.filter(ca__csr__slug=ca_slug).first()
    if format == "crt":
        return HttpResponse(crl.as_der())
    else:
        return HttpResponse(crl.as_pem())
