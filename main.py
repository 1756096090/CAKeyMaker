from services.certificates_service import generate_ca, generate_employee_cert
from utils.utils import read_json, generate_password, export_p12
import pandas as pd

ca_key, ca_cert = generate_ca()
print("Certificado de la CA raíz generado.")

employee_data = read_json("assets/employees.json")
df = pd.DataFrame(employee_data)

passwords = []

for employee in employee_data:
    emp_key, emp_cert = generate_employee_cert(ca_key, ca_cert, employee)
    filename = f"{employee['nombres'].replace(' ', '_')}"
    password = generate_password(16)  # Contraseña de 16 caracteres
    
    passwords.append(password)
    
    export_p12(emp_cert, emp_key, ca_cert, password, filename)
    print(f"Certificado PKCS#12 para {employee['nombres']} generado")
    print(f"Archivo: {filename}.p12 | Contraseña: {password}")

df['password'] = passwords
df = df.drop(columns=['cedula'])
df.to_csv("assets/employees_with_passwords.csv", index=False, encoding="utf-8")
print("Archivo CSV con contraseñas generado.")
