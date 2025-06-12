import os
import base64
import json
import requests
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QFileDialog, QHBoxLayout
)
from db_cliente import get_client_uuid


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
                "uuid": get_client_uuid(),
                "tunnel_id": self.tunnel_id,
                "text": texto,
                "enviado_en": int(time.time() * 1000)
            }
            try:
                self.client.send(json.dumps(mensaje) + "\n")
                self.mostrar_mensaje(f"{texto}")
                self.input_field.clear()
            except Exception as e:
                self.mostrar_mensaje(f"⚠️ Error al enviar el mensaje: {e}")

    def enviar_archivo(self):
        ruta_archivo, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", "Todos los archivos (*)")
        if not ruta_archivo:
            return

        try:
            
            from os.path import basename
            from db_cliente import get_client_uuid

            filename = basename(ruta_archivo)
            with open(ruta_archivo, "rb") as f:
                files = {"file": (filename, f)}
                data = {
                    "alias": self.alias,
                    "tunnel_id": self.tunnel_id,
                    "uuid": get_client_uuid()
                }
                response = requests.post("http://symbolsaps.ddns.net:8000/api/upload-file", files=files, data=data)

            if response.status_code != 200:
                self.mostrar_mensaje("⚠️ Error al subir el archivo al servidor")
                return

            resp_json = response.json()
            url = resp_json.get("url")
            filename = resp_json.get("filename")

            # Enviar por socket solo los metadatos, sin incluir el contenido
            mensaje = {
                "type": "file",
                "from": self.alias,
                "uuid": get_client_uuid(),
                "tunnel_id": self.tunnel_id,
                "filename": filename,
                "url": url,
                "enviado_en": int(time.time() * 1000)
            }
            self.client.send(json.dumps(mensaje) + "\n")
            self.mostrar_mensaje(f"Enviaste un archivo: {filename} 📎")

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
                url = mensaje.get("url")

                if not url:
                    self.mostrar_mensaje(f"{remitente} envió un archivo: {nombre} (sin enlace)")
                    return

                # Mostrar mensaje clickable
                self.mostrar_mensaje(f"{remitente} envió un archivo: {nombre} 📎")
                
                # Intentar descargar al instante
                respuesta = requests.get(f"http://symbolsaps.ddns.net:8000{url}", stream=True)
                if respuesta.status_code != 200:
                    self.mostrar_mensaje("⚠️ No se pudo descargar el archivo.")
                    return

                # Preguntar dónde guardar el archivo
                from PyQt5.QtWidgets import QFileDialog
                ruta_guardado, _ = QFileDialog.getSaveFileName(self, "Guardar archivo recibido", nombre)
                if ruta_guardado:
                    with open(ruta_guardado, "wb") as f:
                        for chunk in respuesta.iter_content(chunk_size=8192):
                            f.write(chunk)
                    self.mostrar_mensaje(f"✅ Archivo guardado como: {ruta_guardado}")

        except Exception as e:
            self.mostrar_mensaje(f"⚠️ Error al procesar mensaje: {e}")

