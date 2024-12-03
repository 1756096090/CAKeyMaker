from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import PrivateFormat, pkcs12
import string
import secrets
import json



def export_p12(cert, key,ca_cert, password, filename):
    # Create custom encryption builder
    encryption = (
        PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(50000)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )

    # Serialize key and certificates into PKCS#12 format
    p12 = serialize_key_and_certificates(
        name=b"employee_cert",
        key=key,
        cert=cert,
        cas=[ca_cert],  # Include CA certificates if needed
        encryption_algorithm=encryption
    )
    
    # Write the serialized data to a .p12 file
    with open(f"{filename}.p12", "wb") as p12_file:
        p12_file.write(p12)
        
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits #+ string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def read_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)