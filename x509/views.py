from django.http import HttpResponse
from rest_framework import permissions, status, viewsets
from rest_framework.response import Response

from .models import CRL, CSR, Certificate, Key
from .serializers import CertificateSerialiser, CSRSerializer, KeySerializer


class KeyViewSet(viewsets.ModelViewSet):
    queryset = Key.objects.all()
    serializer_class = KeySerializer
    permission_classes = [permissions.IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.used:
            return Response(
                data={"detail": "Method not allowed for Key in use"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        return super().destroy(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.used:
            return Response(
                data={"detail": "Method not allowed for Key in use"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        return super().update(request, *args, **kwargs)


class CSRViewSet(viewsets.ModelViewSet):
    queryset = CSR.objects.all()
    serializer_class = CSRSerializer
    permission_classes = [permissions.IsAuthenticated]

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
        return super().destroy(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.signed:
            return Response(
                data={"detail": "Method not allowed for signed CSR"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        return super().update(request, *args, **kwargs)


class CertificateViewSet(viewsets.ModelViewSet):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerialiser
    permission_classes = [permissions.IsAuthenticated]

    def destroy(self, request, *args, **kwargs):
        return Response(
            data={"detail": "Method not allowed for Certificate instance"},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
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
        return Response(
            data=request.data, status=status.HTTP_200_OK
        )

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={'request': request}
        )
        if serializer.is_valid():
            instance = serializer.save()
            if instance.csr.ca:
                crl = CRL(ca=instance)
                crl.save()
            return Response(
                data=serializer.data, status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                data=serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


def crl(_, ca_slug, format: str = "crl"):
    crl = CRL.objects.filter(ca__csr__slug=ca_slug).first()
    if format == "crt":
        return HttpResponse(crl.as_der())
    else:
        return HttpResponse(crl.as_pem())
