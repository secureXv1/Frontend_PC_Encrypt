import socket
import requests
import time
from db_cliente import get_client_uuid, get_connection  # Usa tu conexión existente

def obtener_info_red():
    hostname = socket.gethostname()
    ip_local = "127.0.0.1"
    ip_publica = "No disponible"

    # 🌐 Obtener IP local robusta (funciona en Windows, macOS, Linux)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()
    except Exception as e:
        print("⚠️ No se pudo obtener IP local:", e)

    # ☁️ Obtener IP pública por internet
    try:
        ip_publica = requests.get("https://api.ipify.org").text
    except Exception as e:
        print("⚠️ No se pudo obtener IP pública:", e)

    return hostname, ip_local, ip_publica

def obtener_ubicacion():
    try:
        r = requests.get("https://ipapi.co/json/")
        data = r.json()
        return {
            "ciudad": data.get("city"),
            "region": data.get("region"),
            "pais": data.get("country_name"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude")
        }
    except:
        return {}

def registrar_info_en_db():
    uuid = get_client_uuid()
    hostname, ip_local, ip_publica = obtener_info_red()
    ubicacion = obtener_ubicacion()

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO client_info (
            uuid, hostname, ip_local, ip_publica,
            ciudad, region, pais, latitud, longitud, registrado_en
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        uuid,
        hostname,
        ip_local,
        ip_publica,
        ubicacion.get("ciudad"),
        ubicacion.get("region"),
        ubicacion.get("pais"),
        ubicacion.get("lat"),
        ubicacion.get("lon"),
        int(time.time() * 1000)
    ))
    conn.commit()
    conn.close()
    print("📍 Información de red y ubicación registrada.")

def enviar_info_al_backend():
    uuid = get_client_uuid()
    hostname, ip_local, ip_publica = obtener_info_red()
    ubicacion = obtener_ubicacion()

    payload = {
        "uuid": uuid,
        "hostname": hostname,
        "ip_local": ip_local,
        "ip_publica": ip_publica,
        "ciudad": ubicacion.get("ciudad"),
        "region": ubicacion.get("region"),
        "pais": ubicacion.get("pais"),
        "latitud": ubicacion.get("lat"),
        "longitud": ubicacion.get("lon"),
    }

    try:
        r = requests.post("http://localhost:8000/api/registrar_info_red", json=payload)
        print("📡 Enviado al backend:", r.status_code, r.text)
    except Exception as e:
        print("❌ Error enviando info al backend:", e)
