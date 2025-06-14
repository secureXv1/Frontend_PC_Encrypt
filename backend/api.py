from flask import Flask, request, jsonify
from flask_cors import CORS

from .db import registrar_mensaje

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "http://localhost:5173"}})


@app.route('/api/messages/save', methods=['POST'])
def guardar_mensaje():
    """Endpoint simplificado para registrar mensajes de chat."""
    data = request.json or {}

    tipo = data.get("tipo", "texto")
    contenido = data.get("contenido")

    # Para mensajes de texto aceptamos tanto un string como un dict con clave text
    if tipo == "texto" and isinstance(contenido, dict):
        contenido = contenido.get("text", "")

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
