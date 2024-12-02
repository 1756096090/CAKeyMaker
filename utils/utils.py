from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
import string
import secrets
import json


def export_p12(cert, key, password, filename):
    p12 = pkcs12.serialize_key_and_certificates(
        name=b"employee_cert",
        key=key,
        cert=cert,
        cas=[cert],  
        encryption_algorithm=BestAvailableEncryption(password.encode())  
    )
    with open(f"{filename}.p12", "wb") as p12_file:
        p12_file.write(p12)
        
def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits #+ string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def read_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)