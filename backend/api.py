from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename

from .db import registrar_mensaje, registrar_archivo, _extraer_texto
import json
import os
import time
from uuid import uuid4

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})

# Carpeta para almacenar archivos subidos
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route('/api/messages/save', methods=['POST'])
def guardar_mensaje():
    """Endpoint simplificado para registrar mensajes de chat."""
    data = request.json or {}

    tipo = data.get("tipo") or data.get("type", "texto")
    contenido = data.get("contenido")

    if tipo in ("texto", "text"):
        if contenido is None:
            contenido = data.get("text")
        contenido = _extraer_texto(contenido)
    elif tipo in ("file", "archivo"):
        if contenido is None:
            contenido = data.get("url")
        if isinstance(contenido, dict):
            contenido = contenido.get("url") or contenido.get("filename")
        elif isinstance(contenido, str):
            stripped = contenido.strip()
            if stripped.startswith("{") and stripped.endswith("}"):
                try:
                    tmp = json.loads(stripped)
                    contenido = tmp.get("url") or tmp.get("filename") or contenido
                except Exception:
                    pass

    registrar_mensaje(
        data.get("tunnel_id"),
        data.get("uuid"),
        data.get("alias"),
        contenido,
        tipo,
    )
    return jsonify({"status": "ok"})


@app.route('/api/upload-file', methods=['POST'])
def upload_file():
    """Guarda un archivo y devuelve la URL completa del recurso."""
    archivo = request.files.get("file")
    alias = request.form.get("alias")
    tunnel_id = request.form.get("tunnel_id")
    uuid = request.form.get("uuid")

    if not archivo or not alias or not tunnel_id or not uuid:
        return jsonify({"error": "Faltan datos"}), 400

    original = secure_filename(archivo.filename)
    prefijo = f"{int(time.time()*1000)}_{uuid4().hex[:8]}"
    filename = f"{prefijo}_{original}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    archivo.save(filepath)

    # URL completa para descargar el archivo
    base = request.host_url.rstrip('/')
    url = f"{base}/uploads/{filename}"

    registrar_archivo(filename, url, alias, tunnel_id, uuid)
    return jsonify({"url": url, "filename": filename})


@app.route('/uploads/<path:filename>')
def descargar_archivo(filename):
    return send_from_directory(UPLOAD_FOLDER, filename, as_attachment=True)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
