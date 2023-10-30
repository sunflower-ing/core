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
    extendedKeyUsage = serializers.ChoiceField(
        choices=EKU_CHOICES, allow_null=True
    )
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


class CSRSerializer(serializers.ModelSerializer):
    key = serializers.PrimaryKeyRelatedField(
        many=False, allow_null=True, queryset=Key.objects.all()
    )
    params = CSRParamsSerializer()

    class Meta:
        model = CSR
        fields = (
            "id",
            "name",
            "subject",
            "slug",
            "key",
            "created_at",
            "signed",
            "ca",
            "path_length",
            "params",
            "body",
        )
        read_only_fields = ["slug", "signed", "subject"]


class CertificateSerialiser(serializers.ModelSerializer):
    class Meta:
        model = Certificate
        fields = (
            "id",
            "sn",
            "csr",
            "parent",
            "subject",
            "imported",
            "created_at",
            "revoked",
            "revoked_at",
            "revocation_reason",
            "body",
            "fingerprint",
            "num_signed",
        )
        read_only_fields = ["subject", "sn"]
