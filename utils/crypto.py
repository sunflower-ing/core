import datetime
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DISTINGUISHED_NAME = {
    "countryName": NameOID.COUNTRY_NAME,
    "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "localityName": NameOID.LOCALITY_NAME,
    "organizationName": NameOID.ORGANIZATION_NAME,
    "organizationUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "commonName": NameOID.COMMON_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
    # End-users
    "givenName": NameOID.GIVEN_NAME,
    "surname": NameOID.SURNAME,
}


def _read_pkcs12(
    path: pathlib.Path, password: bytes = None
) -> pkcs12.PKCS12KeyAndCertificates | None:
    with open(path, "rb") as fd:
        return pkcs12.load_pkcs12(data=fd.read(), password=password)


def make_keys(
    algo: str = "RSA", key_size: int = 2048
) -> tuple[
    rsa.RSAPrivateKey | dsa.DSAPrivateKey, rsa.RSAPublicKey | dsa.DSAPublicKey
]:
    if algo == "DSA":
        private_key = dsa.generate_private_key(key_size=key_size)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=key_size
        )

    return private_key, private_key.public_key()


def key_to_pem(
    key: rsa.RSAPrivateKey
    | rsa.RSAPublicKey
    | dsa.DSAPrivateKey
    | dsa.DSAPublicKey,
    private: bool = False,
) -> bytes:
    if private:
        private_key = key  # type: ignore
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_pem

    public_key = key  # type: ignore
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return public_pem


def key_from_pem(
    key_pem: bytes, private: bool = False
) -> rsa.RSAPrivateKey | rsa.RSAPublicKey | dsa.DSAPrivateKey | dsa.DSAPublicKey:  # noqa
    if private:
        private_key = serialization.load_pem_private_key(  # type: ignore  # noqa E501
            key_pem, password=None
        )
        return private_key

    public_key = serialization.load_pem_public_key(key_pem)  # type: ignore
    return public_key


def make_csr(
    private_key: rsa.RSAPrivateKey, data: dict
) -> x509.CertificateSigningRequest | None:
    if not data.get("commonName"):
        return None

    x509_names = [
        x509.NameAttribute(NameOID.COMMON_NAME, data.get("commonName"))
    ]

    for dn_key, dn_value in data.items():
        if dn_value and DISTINGUISHED_NAME.get(dn_key):
            x509_names.append(
                x509.NameAttribute(DISTINGUISHED_NAME[dn_key], dn_value)
            )

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(x509_names)
    )

    signed_csr = csr.sign(private_key, hashes.SHA512())

    return signed_csr


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def csr_from_pem(csr_pem: bytes) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(csr_pem)


def make_cert(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    csr: x509.CertificateSigningRequest,
    data: dict,
) -> x509.Certificate | None:
    cert = (
        x509.CertificateBuilder()
        .public_key(csr.public_key())
        .subject_name(csr.subject)
        .issuer_name(ca_cert.issuer)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=data.days)
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    if data.get("ca"):
        if not data.get("path_length"):
            data.path_length = 1
            # TODO: Get from parent and decrease

        cert = cert.add_extension(
            x509.BasicConstraints(
                ca=True, path_length=data.get("path_length")
            ),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    else:
        cert = cert.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )

        if data.get("extendedKeyUsage") == "client_auth":  # client cert
            cert = cert.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=True,
                    key_agreement=True,
                    content_commitment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )

        if data.get("extendedKeyUsage") == "server_auth":  # server cert
            cert = cert.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_agreement=True,
                    data_encipherment=False,
                    content_commitment=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            ).add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=True,
            )

    cert = cert.sign(private_key=ca_key, algorithm=hashes.SHA512())

    return cert


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_from_pem(cert_pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem)
