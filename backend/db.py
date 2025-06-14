import json
import mysql.connector
import time


def get_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Febrero2025*-+',
        database='securex'
    )


def _extraer_texto(payload):
    """Devuelve el texto plano de un mensaje JSON o valor bruto.

    La función acepta diccionarios o cadenas JSON y devuelve el valor de la
    clave ``text`` o ``contenido`` si están presentes. Si `payload` no es un
    JSON válido se devuelve sin modificar convertido a ``str``.
    """
    if isinstance(payload, dict):
        if "text" in payload:
            return payload["text"]
        if "contenido" in payload:
            return payload["contenido"]
        return str(payload)

    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except Exception:
            return str(payload)

    if isinstance(payload, str):
        stripped = payload.strip()
        if stripped.startswith("{") and stripped.endswith("}"):
            try:
                return _extraer_texto(json.loads(stripped))
            except Exception:
                pass
        return stripped

    return str(payload)


def registrar_mensaje(tunnel_id, client_uuid, alias, contenido, tipo="texto"):
    """Inserta un mensaje normalizando el campo ``contenido``.

    Cuando ``tipo`` corresponde a un mensaje de texto, intenta extraer la parte
    textual ignorando otros campos para evitar almacenar objetos JSON
    completos.
    """
    if tipo in ("texto", "text"):
        contenido = _extraer_texto(contenido)

    conn = get_connection()
    cursor = conn.cursor()
    enviado_en = int(time.time() * 1000)
    cursor.execute(
        """
        INSERT INTO tunnel_messages (tunnel_id, client_uuid, alias, contenido, tipo, enviado_en)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (tunnel_id, client_uuid, alias, contenido, tipo, enviado_en)
    )
    conn.commit()
    cursor.close()
    conn.close()
