from rest_framework import serializers

from .models import CSR, Certificate, Key


class KeySerializer(serializers.ModelSerializer):
    name = serializers.CharField(allow_blank=True)

    class Meta:
        model = Key
        fields = (
            "id",
            "name",
            "algo",
            "length",
            "created_at",
            "used",
            "public",
            "private",
            "fingerprint",
        )


EKU_CHOICES = (
    (None, "CA"),
    ("client_auth", "Client Side"),
    ("server_auth", "Server Side"),
)


class CSRParamsSerializer(serializers.Serializer):
    # Type of certificate (CA if null, Client auth, Server auth)
    # extendedKeyUsage = serializers.ChoiceField(
    #     choices=EKU_CHOICES, allow_null=True
    # )
    # Common DN
    countryName = serializers.CharField(
        max_length=2, min_length=2, allow_blank=True
    )
    stateOrProvinceName = serializers.CharField(allow_blank=True)
    localityName = serializers.CharField(allow_blank=True)
    organizationName = serializers.CharField(allow_blank=True)
    organizationUnitName = serializers.CharField(allow_blank=True)
    # CN is required
    commonName = serializers.CharField()
    # Personalized DN
    emailAddress = serializers.EmailField(allow_blank=True)
    givenName = serializers.CharField(allow_blank=True)
    surname = serializers.CharField(allow_blank=True)
    # Others
    issuerDN = serializers.BooleanField(
        default=False,
        help_text="Take common DN info from issuer's Certificate",
    )
    days = serializers.IntegerField(default=365)
    CRLDistributionPoints = serializers.ListField(
        child=serializers.CharField(allow_blank=True),
        allow_empty=True,
        default=[],
    )
    AuthorityInformationAccess = serializers.ListField(
        child=serializers.CharField(allow_blank=True),
        allow_empty=True,
        default=[],
    )


class KeyUsageSerializer(serializers.Serializer):
    key_cert_sign = serializers.BooleanField(default=False)
    crl_sign = serializers.BooleanField(default=False)
    digital_signature = serializers.BooleanField(default=False)
    key_encipherment = serializers.BooleanField(default=False)
    data_encipherment = serializers.BooleanField(default=False)
    key_agreement = serializers.BooleanField(default=False)
    content_commitment = serializers.BooleanField(default=False)
    encipher_only = serializers.BooleanField(default=False)
    decipher_only = serializers.BooleanField(default=False)


class ExtendedKeyUsageSerializer(serializers.Serializer):
    server_auth = serializers.BooleanField(default=False)
    client_auth = serializers.BooleanField(default=False)
    code_signing = serializers.BooleanField(default=False)
    email_protection = serializers.BooleanField(default=False)
    time_stamping = serializers.BooleanField(default=False)
    ocsp_signing = serializers.BooleanField(default=False)
    smartcard_logon = serializers.BooleanField(default=False)
    kerberos_pkinit_kdc = serializers.BooleanField(default=False)
    ipsec_ike = serializers.BooleanField(default=False)
    certificate_transparency = serializers.BooleanField(default=False)
    any_extended_key_usage = serializers.BooleanField(default=False)


class CSRSerializer(serializers.ModelSerializer):
    key = serializers.PrimaryKeyRelatedField(
        many=False, allow_null=True, queryset=Key.objects.all()
    )
    params = CSRParamsSerializer()
    key_usage = KeyUsageSerializer()
    extended_key_usage = ExtendedKeyUsageSerializer()

    class Meta:
        model = CSR
        fields = (
            "id",
            "name",
            "subject",
            "key",
            "created_at",
            "signed",
            "ca",
            "path_length",
            "params",
            "key_usage",
            "extended_key_usage",
            "body",
        )
        read_only_fields = [
            "signed",
            "subject",
            "body",
            "created_at",
        ]


class CertificateSerialiser(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = (
            "id",
            "sn",
            "csr",
            "key",
            "parent",
            "subject",
            "imported",
            "created_at",
            "expires_at",
            "revoked",
            "revoked_at",
            "revocation_reason",
            "body",
            "fingerprint",
            "num_signed",
        )
        read_only_fields = ["subject", "sn", "expires_at"]
