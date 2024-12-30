import random
import string

def generar_clave_aleatoria():
    mayusculas = string.ascii_uppercase
    minusculas = string.ascii_lowercase
    numeros = string.digits
    especiales = "!@#$%^&*()_-+=<>?"

    # Elegir al menos un carácter de cada tipo
    clave = [
        random.choice(mayusculas),
        random.choice(minusculas),
        random.choice(numeros),
        random.choice(especiales)
    ]
    
    # Llenar el resto de la clave con caracteres aleatorios de los tres primeros grupos
    todos_caracteres = mayusculas + minusculas + numeros
    clave += random.choices(todos_caracteres, k=8)

    # Mezclar los caracteres para que estén en orden aleatorio
    random.shuffle(clave)

    return ''.join(clave)

# Generar y mostrar la clave
clave = generar_clave_aleatoria()
print(f"Clave generada: {clave}")
