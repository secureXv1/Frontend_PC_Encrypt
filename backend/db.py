import mysql.connector
import json
import time


def get_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Febrero2025*-+',
        database='securex'
    )


def registrar_mensaje(tunnel_id, client_uuid, alias, contenido, tipo="texto"):
    """Inserta un mensaje normalizando el campo de contenido.

    Si `tipo` corresponde a un mensaje de texto y el contenido parece un JSON
    serializado, se extrae el valor de la clave ``text`` para evitar almacenar
    todo el objeto.
    """
    if tipo in ("texto", "text"):
        if isinstance(contenido, dict):
            contenido = contenido.get("text", str(contenido))
        elif isinstance(contenido, bytes):
            contenido = contenido.decode("utf-8", errors="ignore")
        elif isinstance(contenido, str):
            stripped = contenido.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    data = json.loads(stripped)
                    if isinstance(data, dict) and "text" in data:
                        contenido = data["text"]
                except Exception:
                    pass

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
