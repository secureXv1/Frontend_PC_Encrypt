import socket
from app_logger import logger
try:
    import requests
except Exception as e:  # pragma: no cover - env may lack requests
    requests = None
    logger.warning(f"No se pudo importar requests: {e}")
import time
from db_cliente import get_client_uuid, get_connection  # Usa tu conexión existente

def obtener_info_red():
    logger.info("Obteniendo hostname...")
    hostname = socket.gethostname()
    logger.info(f"Hostname: {hostname}")
    ip_local = "127.0.0.1"
    ip_publica = "No disponible"

    # 🌐 Obtener IP local robusta (funciona en Windows, macOS, Linux)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()
    except Exception as e:
        logger.warning(f"No se pudo obtener IP local: {e}")

    # ☁️ Obtener IP pública por internet
    try:
        if requests:
            ip_publica = requests.get("https://api.ipify.org").text
        else:
            raise RuntimeError("módulo requests no disponible")
    except Exception as e:
        logger.warning(f"No se pudo obtener IP pública: {e}")

    return hostname, ip_local, ip_publica

def obtener_ubicacion():
    try:
        if requests:
            r = requests.get("https://ipapi.co/json/")
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            data = r.json()
        else:
            raise RuntimeError("módulo requests no disponible")

        return {
            "ciudad": data.get("city"),
            "region": data.get("region"),
            "pais": data.get("country_name"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude")
        }
    except Exception as e:
        logger.warning(f"No se pudo obtener ubicación: {e}")
        return {}

def registrar_info_en_db():
    logger.info("Registrando información de red en la base de datos...")
    uuid = get_client_uuid()
    hostname, ip_local, ip_publica = obtener_info_red()
    ubicacion = obtener_ubicacion()

    try:
        logger.info("Conectando a la base de datos...")
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
        logger.info("Información de red y ubicación registrada.")
    except Exception as e:
        logger.error(f"Error registrando info de red en la DB: {e}")

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
        if not requests:
            raise RuntimeError("módulo requests no disponible")
        r = requests.post("http://localhost:8000/api/registrar_info_red", json=payload)
        logger.info(f"Enviado al backend: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error enviando info al backend: {e}")
