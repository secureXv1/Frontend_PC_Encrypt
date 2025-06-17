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
    import platform
    print("🔍 Obteniendo hostname...")
    hostname = socket.gethostname()
    ip_local = "127.0.0.1"
    ip_publica = "No disponible"

    # IP local
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_local = s.getsockname()[0]
        s.close()
    except:
        pass

    # IP pública
    try:
        ip_publica = requests.get("https://api.ipify.org").text
    except:
        pass

    # Red Wi-Fi
    red_wifi = "No disponible"
    so = platform.system()
    if so == "Darwin":  # macOS
        red_wifi = obtener_red_wifi()
    elif so == "Linux":
        red_wifi = obtener_red_wifi()
    elif so == "Windows":
        red_wifi = obtener_red_wifi_windows()

    return hostname, ip_local, ip_publica, red_wifi

def obtener_ubicacion():
    if not requests:
        logger.warning("módulo requests no disponible")
        return {}

    # Intenta primero con ipapi.co y luego ipinfo.io como respaldo
    services = [
        ("https://ipapi.co/json/", lambda d: {
            "ciudad": d.get("city"),
            "region": d.get("region"),
            "pais": d.get("country_name"),
            "lat": d.get("latitude"),
            "lon": d.get("longitude"),
        }),
        ("https://ipinfo.io/json", lambda d: {
            "ciudad": d.get("city"),
            "region": d.get("region"),
            "pais": d.get("country"),
            "lat": (d.get("loc", ",").split(",")[0] if d.get("loc") else None),
            "lon": (d.get("loc", ",").split(",")[1] if d.get("loc") else None),
        }),
    ]

    for url, parser in services:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200:
                raise RuntimeError(f"HTTP {r.status_code}")
            data = r.json()
            return parser(data)
        except Exception as e:
            logger.warning(f"No se pudo obtener ubicación desde {url}: {e}")

    return {}

def registrar_info_en_db():
    logger.info("Registrando información de red en la base de datos...")
    uuid = get_client_uuid()
    hostname, ip_local, ip_publica, red_wifi = obtener_info_red()
    ubicacion = obtener_ubicacion()

    try:
        logger.info("Conectando a la base de datos...")
        conn = get_connection()
        logger.info("Conexión establecida, insertando registro...")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO client_info (
                uuid, hostname, ip_local, ip_publica,
                ciudad, region, pais, latitud, longitud, red_wifi, registrado_en
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                uuid,
                hostname,
                ip_local,
                ip_publica,
                ubicacion.get("ciudad"),
                ubicacion.get("region"),
                ubicacion.get("pais"),
                ubicacion.get("lat"),
                ubicacion.get("lon"),
                red_wifi,  # ← Este campo faltaba
                int(time.time() * 1000),
            ),
        )
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Información de red y ubicación registrada.")
    except Exception as e:
        logger.error(
            f"Error registrando info de red en la DB: {e}", exc_info=True
        )

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
        r = requests.post("http://localhost:8000/api/registrar_info_red", json=payload, timeout=5)
        logger.info(f"Enviado al backend: {r.status_code} {r.text}")
    except Exception as e:
        logger.error(f"Error enviando info al backend: {e}")

import subprocess

def obtener_red_wifi():
    try:
        resultado = subprocess.check_output(
            ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
            stderr=subprocess.DEVNULL
        ).decode()
        for linea in resultado.splitlines():
            if " SSID:" in linea:
                return linea.split("SSID:")[1].strip()
    except:
        pass

    # Linux alternativo
    try:
        resultado = subprocess.check_output(["iwgetid", "-r"]).decode().strip()
        if resultado:
            return resultado
    except:
        pass

    return "No disponible"

def obtener_red_wifi_windows():
    try:
        output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
        for line in output.splitlines():
            if "SSID" in line and "BSSID" not in line:
                return line.split(":")[1].strip()
    except:
        pass
    return "No disponible"
