import os
import base64
import json
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QFileDialog, QHBoxLayout
)

class ChatWindow(QWidget):
    def __init__(self, alias, client, tunnel_id, uuid):
        super().__init__()
        self.alias = alias
        self.client = client  # instancia de TunnelClient
        self.tunnel_id = tunnel_id
        self.uuid = uuid

        self.setWindowTitle(f"Túnel - {alias}")
        self.resize(500, 350)

        # Layout principal
        layout = QVBoxLayout()
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Escribe un mensaje...")
        self.input_field.returnPressed.connect(self.enviar_mensaje)

        # Botón de adjuntar archivo
        self.attach_button = QPushButton("📎")
        self.attach_button.clicked.connect(self.enviar_archivo)

        # Barra inferior con input y botón
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.input_field)
        input_layout.addWidget(self.attach_button)

        layout.addWidget(self.chat_area)
        layout.addLayout(input_layout)
        self.setLayout(layout)

    def mostrar_mensaje(self, texto):
        self.chat_area.append(texto)

    def enviar_mensaje(self):
        texto = self.input_field.text().strip()
        if texto:
            mensaje = {
                "type": "text",
                "from": self.alias,
                "text": texto
            }
            try:
                self.client.send(json.dumps(mensaje) + "\n")
                self.mostrar_mensaje(f"🧑 Tú: {texto}")
                self.input_field.clear()
            except Exception as e:
                self.mostrar_mensaje(f"⚠️ Error al enviar el mensaje: {e}")

    def enviar_archivo(self):
        ruta_archivo, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", "Todos los archivos (*)")
        if not ruta_archivo:
            return

        try:
            with open(ruta_archivo, "rb") as f:
                contenido = f.read()

            b64_data = base64.b64encode(contenido).decode()
            nombre = os.path.basename(ruta_archivo)
            ext = os.path.splitext(nombre)[1]

            mensaje = {
                "type": "file",
                "from": self.alias,
                "filename": nombre,
                "ext": ext,
                "data": b64_data
            }

            self.client.send(json.dumps(mensaje) + "\n")
            self.mostrar_mensaje(f"🧑 Tú enviaste un archivo: {nombre}")
        except Exception as e:
            self.mostrar_mensaje(f"⚠️ Error al adjuntar archivo: {e}")

    def procesar_mensaje(self, mensaje_json):
        try:
            mensaje = json.loads(mensaje_json)
            tipo = mensaje.get("type", "text")
            remitente = mensaje.get("from", "Desconocido")

            if tipo == "text":
                texto = mensaje.get("text", "")
                self.mostrar_mensaje(f"{remitente}: {texto}")

            elif tipo == "file":
                nombre = mensaje.get("filename", "archivo")
                b64_data = mensaje.get("data", "")

                self.mostrar_mensaje(f"{remitente} envió un archivo: {nombre} 📎")

                ruta_guardado, _ = QFileDialog.getSaveFileName(self, "Guardar archivo recibido", nombre)
                if ruta_guardado:
                    with open(ruta_guardado, "wb") as f:
                        f.write(base64.b64decode(b64_data))
                    self.mostrar_mensaje(f"✅ Archivo guardado como: {ruta_guardado}")
        except Exception as e:
            self.mostrar_mensaje(f"⚠️ Error al procesar mensaje: {e}")
