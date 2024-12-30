from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier
import os

def generate_ca():
    # CA generation code remains the same
    ca_private_key_path = "assets/ca_files/ca_private_key.pem"
    ca_certificate_path = "assets/ca_files/ca_certificate.pem"
    
    os.makedirs("assets/ca_files", exist_ok=True)
    
    if os.path.exists(ca_private_key_path) and os.path.exists(ca_certificate_path):
        with open(ca_private_key_path, "rb") as key_file:
            ca_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        
        with open(ca_certificate_path, "rb") as cert_file:
            ca_certificate = x509.load_pem_x509_certificate(
                cert_file.read(),
                backend=default_backend()
            )
        
        return ca_key, ca_certificate
    
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pichincha"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Quito"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ciemtelcom"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Ciemtelcom CA"),
    ])
    
    ca_certificate = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(ca_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.now(timezone.utc))\
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))\
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)\
        .sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
    
    with open(ca_private_key_path, "wb") as key_file:
        key_file.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    with open(ca_certificate_path, "wb") as cert_file:
        cert_file.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    
    return ca_key, ca_certificate

def generate_employee_cert(ca_key, ca_cert, employee):
    # Generar clave privada del empleado
    emp_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # OIDs específicos para Adobe
    ADOBE_PPKLIT = ObjectIdentifier("1.2.840.113583.1.1.5")
    ADOBE_SIGNING = ObjectIdentifier("1.2.840.113583.1.1.9.1")
    
    # Construir el subject con formato específico
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pichincha"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Quito"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mi Empresa"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{employee['nombres']}"),
        x509.NameAttribute(NameOID.TITLE, employee['cargo']),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, employee['mail'])
    ])

    builder = x509.CertificateBuilder()
    
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(emp_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    
    builder = builder.not_valid_before(datetime.now(timezone.utc))
    builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )
    
    # Extended Key Usage específico para firma digital
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ObjectIdentifier("1.3.6.1.4.1.311.10.3.12"),  # Microsoft Document Signing
            ADOBE_SIGNING
        ]),
        critical=False
    )

    builder = builder.add_extension(
        x509.UnrecognizedExtension(ADOBE_PPKLIT, b'\x30\x03\x02\x01\x01'),
        critical=False
    )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(emp_key.public_key()),
        critical=False
    )
    
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )

    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                ObjectIdentifier("2.16.840.1.113733.1.7.23.3"),
                None
            )
        ]),
        critical=False
    )

    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return emp_key, certificate