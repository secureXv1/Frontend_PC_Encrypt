import mysql.connector
import os
import requests

def get_connection():
    return mysql.connector.connect(
        host='symbolsaps.ddns.net',
        user='admin',
        password='Febrero2025*-+',
        database='securex'
    )

# 🚀 Crear un nuevo túnel
def crear_tunel(nombre, password_hash):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tunnels (name, password_hash) VALUES (%s, %s)",
        (nombre, password_hash)
    )
    conn.commit()
    tunnel_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return tunnel_id

# 🔎 Consultar túnel por nombre
def obtener_tunel_por_nombre(nombre):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM tunnels WHERE name = %s", (nombre,))
    tunel = cursor.fetchone()
    cursor.close()
    conn.close()
    return tunel

# 💾 Guardar el UUID localmente
def guardar_uuid_localmente(uuid):
    path = os.path.expanduser("~/.betty")
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, ".uuid"), "w") as f:
        f.write(uuid)

# 📥 Obtener UUID guardado localmente
def get_client_uuid():
    path = os.path.expanduser("~/.betty/.uuid")
    if os.path.exists(path):
        with open(path, "r") as f:
            return f.read().strip()
    else:
        return None

# 🌐 Registrar cliente en el backend
def registrar_cliente(uuid, hostname, sistema):
    try:
        response = requests.post(
            "http://symbolsaps.ddns.net:8000/api/registrar_cliente",
            json={
                "uuid": uuid,
                "hostname": hostname,
                "sistema": sistema
            }
        )
        response.raise_for_status()
        print("✅ Cliente registrado correctamente en el backend.")
    except Exception as e:
        print(f"❌ Error al registrar cliente en el backend: {e}")

def registrar_alias_cliente(uuid, tunnel_id, alias):
    import requests
    payload = {
        "uuid": uuid,
        "tunnel_id": tunnel_id,
        "alias": alias
    }
    try:
        response = requests.post("http://symbolsaps.ddns.net:8000/api/registrar_alias", json=payload)
        response.raise_for_status()
        print("✅ Alias registrado correctamente")
    except Exception as e:
        print("❌ Error al registrar alias:", e)
