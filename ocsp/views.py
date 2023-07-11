from cryptography.x509 import ocsp
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework import permissions, viewsets

from utils.crypto import (
    create_ocsp_response,
    ocsp_response_to_der,
    read_ocsp_request,
)
from x509.models import Certificate

from .models import RequestLog, Source
from .serializers import RequestLogSerializer, SourceSerializer


@csrf_exempt
def ocsp_view(request):
    print(f"REMOTE_ADDR: {request.META.get('REMOTE_ADDR')}")
    print(f"REMOTE_HOST: {request.META.get('REMOTE_HOST')}")
    if request.method == "POST":
        req_data = read_ocsp_request(request.body)
        try:
            cert = Certificate.objects.get(sn=req_data.get("serial_number"))
            if not cert.revoked:
                response = create_ocsp_response(
                    cert=cert.as_object(),
                    issuer=cert.parent.as_object(),
                    cert_status=ocsp.OCSPCertStatus.GOOD,
                    responder_cert=cert.parent.as_object(),
                    responder_key=cert.parent.csr.key.private_as_object(),
                )
            else:
                response = create_ocsp_response(
                    cert=cert.as_object(),
                    issuer=cert.parent.as_object(),
                    cert_status=ocsp.OCSPCertStatus.REVOKED,
                    responder_cert=cert.parent.as_object(),
                    responder_key=cert.parent.csr.key.private_as_object(),
                    revocation_time=cert.revoked_at,
                    revocation_reason=cert.revocation_reason,
                )

            log = RequestLog(
                cert=cert,
                host=request.META.get('REMOTE_HOST'),
                addr=request.META.get('REMOTE_ADDR'),
            )
            log.save()

            return HttpResponse(ocsp_response_to_der(response))

        except Certificate.DoesNotExist:
            response = ocsp.OCSPResponseBuilder.build_unsuccessful(
                ocsp.OCSPResponseStatus.INTERNAL_ERROR
            )
            return HttpResponse(ocsp_response_to_der(response))

    response = ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.MALFORMED_REQUEST
    )
    return HttpResponse(ocsp_response_to_der(response))


class SourceViewSet(viewsets.ModelViewSet):
    queryset = Source.objects.all()
    serializer_class = SourceSerializer
    permission_classes = [permissions.IsAuthenticated]


class RequestLogViewSet(viewsets.ModelViewSet):
    queryset = RequestLog.objects.all()
    serializer_class = RequestLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    http_method_names = ["get"]
