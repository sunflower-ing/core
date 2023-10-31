import binascii
import datetime
import os
import pathlib
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp
from cryptography.x509.extensions import _key_identifier_from_public_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LOCALITY_DN = {
    "countryName": NameOID.COUNTRY_NAME,
    "stateOrProvinceName": NameOID.STATE_OR_PROVINCE_NAME,
    "localityName": NameOID.LOCALITY_NAME,
}

ORGANIZATION_DN = {
    "organizationName": NameOID.ORGANIZATION_NAME,
    "organizationUnitName": NameOID.ORGANIZATIONAL_UNIT_NAME,
}

ENDUSER_DN = {
    "commonName": NameOID.COMMON_NAME,
    "emailAddress": NameOID.EMAIL_ADDRESS,
    "givenName": NameOID.GIVEN_NAME,
    "surname": NameOID.SURNAME,
}

DISTINGUISHED_NAME = LOCALITY_DN | ORGANIZATION_DN | ENDUSER_DN

REVOCATION_REASONS = {reason.name: reason.value for reason in x509.ReasonFlags}

HASHES = {
    "sha1": hashes.SHA1,
    "sha512-224": hashes.SHA512_224,
    "sha512-256": hashes.SHA512_256,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
    "sha3-224": hashes.SHA3_224,
    "sha3-256": hashes.SHA3_256,
    "sha3-384": hashes.SHA3_384,
    "sha3-512": hashes.SHA3_512,
    "shake128": hashes.SHAKE128,
    "shake256": hashes.SHAKE256,
    "md5": hashes.MD5,
    "blake2b": hashes.BLAKE2b,
    "blake2s": hashes.BLAKE2s,
    "sm3": hashes.SM3,
}


def _read_pkcs12(
    path: pathlib.Path, password: bytes = None
) -> pkcs12.PKCS12KeyAndCertificates | None:
    with open(path, "rb") as fd:
        return pkcs12.load_pkcs12(data=fd.read(), password=password)


def _random_serial(length: int = 7) -> int:
    return int.from_bytes(os.urandom(length), byteorder=sys.byteorder)


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

    x509_names = []

    for dn_key, dn_value in data.items():
        if dn_value and DISTINGUISHED_NAME.get(dn_key):
            x509_names.append(
                x509.NameAttribute(DISTINGUISHED_NAME[dn_key], dn_value)
            )

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(x509_names)
    )

    signed_csr = csr.sign(private_key, hashes.SHA256())

    return signed_csr


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_bytes(serialization.Encoding.PEM)


def csr_from_pem(csr_pem: bytes) -> x509.CertificateSigningRequest:
    return x509.load_pem_x509_csr(csr_pem)


def make_cert(
    ca_cert: x509.Certificate | x509.CertificateSigningRequest,
    ca_key: rsa.RSAPrivateKey | dsa.DSAPrivateKey,
    csr: x509.CertificateSigningRequest,
    data: dict,
    self_sign: bool = False,
    issuer_dn: bool = False,
) -> x509.Certificate | None:
    cert = (
        x509.CertificateBuilder()
        .public_key(csr.public_key())
        # .subject_name(csr.subject)
        .serial_number(_random_serial())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow()
            + datetime.timedelta(days=data.get("days"))
        )
        .add_extension(  # FIXME: there MUST be current cert's key
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
    )

    if issuer_dn:
        x509_names = []

        for dn_key, dn_value in (LOCALITY_DN | ORGANIZATION_DN).items():
            attrs = ca_cert.subject.get_attributes_for_oid(dn_value)
            if attrs:
                for attr in attrs:
                    x509_names.append(
                        x509.NameAttribute(
                            DISTINGUISHED_NAME[dn_key], attr.value
                        )
                    )

        for dn_key, dn_value in data.items():
            if dn_value and ENDUSER_DN.get(dn_key):
                x509_names.append(
                    x509.NameAttribute(DISTINGUISHED_NAME[dn_key], dn_value)
                )

        cert = cert.subject_name(x509.Name(x509_names))

    else:
        cert = cert.subject_name(csr.subject)

    if self_sign:
        cert = cert.issuer_name(csr.subject)
    else:
        cert = cert.issuer_name(ca_cert.subject)

    if data.get("ca") is True:
        if not data.get("path_length"):
            data.path_length = 1
            # TODO: Get from parent and decrease

        cert = (
            cert.add_extension(
                x509.BasicConstraints(
                    ca=True, path_length=data.get("path_length")
                ),
                critical=True,
            )
            .add_extension(
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
            .add_extension(
                x509.ExtendedKeyUsage(([ExtendedKeyUsageOID.OCSP_SIGNING]))
            )
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

    if data.get("CRLDistributionPoints"):
        if not isinstance(data.get("CRLDistributionPoints"), list):
            data["CRLDistributionPoints"] = [data.get("CRLDistributionPoints")]

        crl_dp = []
        for item in data.get("CRLDistributionPoints"):
            crl_dp.append(
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier(item)],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=None,
                )
            )
        cert = cert.add_extension(
            x509.CRLDistributionPoints(crl_dp), critical=False
        )

    if data.get("AuthorityInformationAccess"):
        if not isinstance(data.get("AuthorityInformationAccess"), list):
            data["AuthorityInformationAccess"] = [
                data.get("AuthorityInformationAccess")
            ]

        ocsp_urls = []
        for item in data.get("AuthorityInformationAccess"):
            ocsp_urls.append(
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier(item),
                )
            )

        cert = cert.add_extension(
            x509.AuthorityInformationAccess(ocsp_urls), critical=False
        )

    cert = cert.sign(private_key=ca_key, algorithm=hashes.SHA256())

    return cert


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_from_pem(cert_pem: bytes) -> x509.Certificate:
    return x509.load_pem_x509_certificate(cert_pem)


def make_crl(
    ca_cert,
    ca_key,
    certificates_list: list[(x509.Certificate, str, datetime.datetime)] = None,
) -> x509.CertificateRevocationList:
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(datetime.datetime.now())
        .next_update(datetime.datetime.now() + datetime.timedelta(1, 0, 0))
        # TODO: move next_update delta to config
    )

    if certificates_list:
        for cert, reason, date in certificates_list:
            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(cert.serial_number)
                .revocation_date(date)
                .add_extension(
                    x509.CRLReason(getattr(x509.ReasonFlags, reason)),
                    critical=False,
                )
            ).build()

            crl = crl.add_revoked_certificate(revoked_cert)

    crl = crl.sign(private_key=ca_key, algorithm=hashes.SHA256())

    return crl


def crl_to_pem(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(serialization.Encoding.PEM)


def crl_to_der(crl: x509.CertificateRevocationList) -> bytes:
    return crl.public_bytes(serialization.Encoding.DER)


def crl_from_pem(crl_pem: bytes) -> x509.CertificateRevocationList:
    return x509.load_pem_x509_crl(crl_pem)


def crl_from_der(crl_der: bytes) -> x509.CertificateRevocationList:
    return x509.load_der_x509_crl(crl_der)


def read_ocsp_request(data: bytes) -> dict:  # TODO: Make a typed object
    req = ocsp.load_der_ocsp_request(data)
    return {
        "issuer_key_hash": req.issuer_key_hash.hex(),
        "issuer_name_hash": req.issuer_name_hash.hex(),
        "hash_algorithm": req.hash_algorithm.name,
        "serial_number": req.serial_number,
        "extensions": [{ext.oid._name: ext.value} for ext in req.extensions],
    }


def create_ocsp_response(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    cert_status: ocsp.OCSPCertStatus,
    responder_cert: x509.Certificate,
    responder_key: rsa.RSAPrivateKey | dsa.DSAPrivateKey,
    revocation_time: datetime.datetime = None,
    revocation_reason: str = None,
    nonce: x509.OCSPNonce = None,
    algo: str = "sha1",
) -> ocsp.OCSPResponse:
    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=cert,
        issuer=issuer,
        algorithm=HASHES[algo](),
        cert_status=cert_status,
        this_update=datetime.datetime.now(),
        next_update=datetime.datetime.now() + datetime.timedelta(minutes=1),
        revocation_time=revocation_time,
        revocation_reason=getattr(x509.ReasonFlags, revocation_reason)
        if revocation_reason
        else None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, responder_cert)
    if nonce:
        builder = builder.add_extension(nonce, critical=False)

    response = builder.sign(responder_key, hashes.SHA256())
    return response


def ocsp_response_to_der(response: ocsp.OCSPResponse) -> bytes:
    return response.public_bytes(serialization.Encoding.DER)


# TODO: make hash type parameter
def get_cert_fingerprint(cert: x509.Certificate) -> bytes:
    return binascii.hexlify(cert.fingerprint(hashes.SHA1()))  # nosec


# TODO: make hash type parameter
def get_cert_subject_fingerprint(cert: x509.Certificate) -> bytes:
    digest = hashes.Hash(hashes.SHA1())  # nosec
    digest.update(cert.subject.public_bytes())
    return binascii.hexlify(digest.finalize())


# TODO: make hash type parameter + combine with previous
def get_cert_issuer_fingerprint(cert: x509.Certificate) -> bytes:
    digest = hashes.Hash(hashes.SHA1())  # nosec
    digest.update(cert.issuer.public_bytes())
    return binascii.hexlify(digest.finalize())


def get_key_fingerprint(key: rsa.RSAPublicKey | dsa.DSAPublicKey) -> bytes:
    return binascii.hexlify(_key_identifier_from_public_key(key))
