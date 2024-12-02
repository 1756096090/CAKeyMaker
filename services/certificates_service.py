

from cryptography import x509 
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives import serialization
import os
 

def generate_ca():
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
        public_exponent=65537,  # Pequeño número primo (p-1)*(q-1)
        key_size=2048,  # 2048 bits
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Pichincha"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Quito"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mi Empresa CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Mi Empresa CA Root"),
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
    emp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EC"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mi Empresa"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"{employee['nombres']} {employee['apellidos']}"),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, employee['cedula']),
        x509.NameAttribute(NameOID.TITLE, employee['cargo']),
    ])
    
    # Certificado del empleado firmado por la CA
    employee_cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(ca_cert.subject)\
        .public_key(emp_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.now(timezone.utc))\
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))\
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, # para firmar documentos
                content_commitment=True,  # para demostrar que el contenido se realizo en un día específico sin mostrar el contenido
                key_encipherment=True, # Cifirado de claves simétricas
                data_encipherment=False, # Cifrar datos en la clave pública
                key_agreement=False,
                key_cert_sign=False, 
                crl_sign=False,
                encipher_only=False,  # Obligatorio
                decipher_only=False   # Obligatorio
            ),
            critical=True
        )\
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=True
        )\
        .sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
    
    return emp_key, employee_cert