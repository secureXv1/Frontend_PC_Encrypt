from flask import Flask, request, jsonify
from flask_cors import CORS

from .db import registrar_mensaje, _extraer_texto

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})


@app.route('/api/messages/save', methods=['POST'])
def guardar_mensaje():
    """Endpoint simplificado para registrar mensajes de chat."""
    data = request.json or {}

    tipo = data.get("tipo", "texto")
    contenido = data.get("contenido")

    if tipo in ("texto", "text"):
        if contenido is None:
            contenido = data.get("text")
        contenido = _extraer_texto(contenido)

    registrar_mensaje(
        data.get("tunnel_id"),
        data.get("uuid"),
        data.get("alias"),
        contenido,
        tipo,
    )
    return jsonify({"status": "ok"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
