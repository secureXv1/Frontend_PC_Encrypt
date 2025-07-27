import os
import base64
import json
import requests
import time
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QFileDialog,
    QHBoxLayout, QScrollArea, QSpacerItem, QSizePolicy, QLabel
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QPainter
from db_cliente import get_client_uuid
from message_bubble import MessageBubble


class ChatWindow(QWidget):
    def __init__(self, alias, client, tunnel_id, uuid, on_file_event=None, on_receive_callback=None):
        super().__init__()
        self.alias = alias
        self.client = client  # instancia de TunnelClient
        self.tunnel_id = tunnel_id
        self.uuid = uuid
        self.on_file_event = on_file_event

        self.setWindowTitle(f"Túnel - {alias}")
        self.resize(500, 350)

        layout = QVBoxLayout()

        # Fondo con imagen
        self.background_label = QLabel(self)
        self.background_label.setGeometry(0, 0, self.width(), self.height())
        self.background_label.lower()
        self.update_background_image()

        # ÁREA DE MENSAJES (reemplazo moderno)
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("""
            QScrollArea {
                background-color: rgba(30, 30, 30, 200); /* más claro */
                border: none;
            }
            QWidget {
                background-color: rgba(0, 0, 0, 50); /* muy transparente */
            }
        """)

        self.bubble_container = QWidget()
        self.bubble_layout = QVBoxLayout(self.bubble_container)
        self.bubble_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.bubble_container)

        layout.addWidget(self.scroll_area)

        # INPUT Y BOTONES
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Escribe un mensaje...")
        self.input_field.returnPressed.connect(self.enviar_mensaje)

        self.attach_button = QPushButton("📎")
        self.attach_button.clicked.connect(self.enviar_archivo)
        self.attach_button.setMinimumWidth(30)

        self.send_button = QPushButton("Enviar")
        self.send_button.clicked.connect(self.enviar_mensaje)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.attach_button, 0)
        input_layout.addWidget(self.input_field, 1)
        input_layout.addWidget(self.send_button, 0)

        layout.addLayout(input_layout)
        self.setLayout(layout)

        if client and on_receive_callback:
            client.on_receive_callback = on_receive_callback


    def mostrar_mensaje(self, texto, sender, is_sender=False, timestamp=None, url=None):
        bubble = MessageBubble(texto, sender, is_sender, timestamp, url, self.download_file)
        self.bubble_layout.addWidget(bubble)
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())


    def enviar_mensaje(self):
        texto = self.input_field.text().strip()
        if texto:
            mensaje = {
                "type": "text",
                "from": self.alias,
                "uuid": get_client_uuid(),
                "tunnel_id": self.tunnel_id,
                "text": texto,
                "enviado_en": int(time.time() * 1000),
                "tipo": "texto",
                "contenido": texto,
            }
            try:
                # Enviar por el cliente sin agregar nueva línea extra
                self.client.send(mensaje)
                self.mostrar_mensaje(texto, self.alias, True, int(time.time() * 1000))
                self.input_field.clear()

            except Exception as e:
                self.mostrar_mensaje(f"⚠️ Error al enviar el mensaje: {e}", "Sistema", True)


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

            # Enviar por socket solo los metadatos, sin incluir el contenido del archivo
            mensaje = {
                "type": "file",
                "from": self.alias,
                "uuid": get_client_uuid(),
                "tunnel_id": self.tunnel_id,
                "filename": filename,
                "url": url,
                "enviado_en": int(time.time() * 1000),
                "tipo": "file",
                "contenido": url,
            }
            self.client.send(mensaje)
            self.mostrar_mensaje(filename, self.alias, True, int(time.time() * 1000), url)
            if self.on_file_event:
                self.on_file_event(self.tunnel_id, filename, url)

        except Exception as e:
            self.mostrar_mensaje(f"⚠️ Error al adjuntar archivo: {e}")


    def procesar_mensaje(self, mensaje_json):
        try:
            mensaje = json.loads(mensaje_json)

            tipo = mensaje.get("type") or mensaje.get("tipo", "text")
            remitente = mensaje.get("from", "Desconocido")

            if tipo == "text":
                texto = mensaje.get("text", "")
                self.mostrar_mensaje(texto, remitente, False, mensaje.get("enviado_en"))

            elif tipo == "file":
                nombre = mensaje.get("filename", "archivo")
                url = mensaje.get("url")

                if not url:
                    self.mostrar_mensaje(
                        f"{remitente} envió un archivo: {nombre} (sin enlace)",
                        remitente,
                        False,
                        mensaje.get("enviado_en"),
                    )
                    return

                self.mostrar_mensaje(
                    f"{remitente} envió un archivo: {nombre}",
                    remitente,
                    False,
                    mensaje.get("enviado_en"),
                    url,
                )
                if self.on_file_event:
                    self.on_file_event(self.tunnel_id, nombre, url)

        except Exception as e:
            self.mostrar_mensaje(f"⚠️ Error al procesar mensaje: {e}", "Sistema", True)


    def download_file(self, url, nombre):
        try:
            if not url.startswith("http"):
                url = f"http://symbolsaps.ddns.net:8000{url}"
            respuesta = requests.get(url, stream=True)
            if respuesta.status_code != 200:
                self.mostrar_mensaje("⚠️ No se pudo descargar el archivo.")
                return

            ruta_guardado, _ = QFileDialog.getSaveFileName(self, "Guardar archivo recibido", nombre)
            if ruta_guardado:
                from PyQt5.QtWidgets import QProgressDialog

                total_size = int(respuesta.headers.get('content-length', 0))
                progress = QProgressDialog("Descargando archivo...", "Cancelar", 0, total_size, self)
                progress.setWindowTitle("Progreso de descarga")
                progress.setWindowModality(True)
                progress.setMinimumDuration(0)
                progress.setValue(0)

                with open(ruta_guardado, "wb") as f:
                    downloaded = 0
                    for chunk in respuesta.iter_content(chunk_size=8192):
                        if progress.wasCanceled():
                            self.mostrar_mensaje("⛔ Descarga cancelada por el usuario.")
                            return
                        f.write(chunk)
                        downloaded += len(chunk)
                        progress.setValue(downloaded)

                progress.close()
                self.mostrar_mensaje(f"✅ Archivo guardado como: {ruta_guardado}", "Sistema", True)
        except Exception as e:
            self.mostrar_mensaje(f"⚠️ Error al descargar archivo: {e}", "Sistema", True)


    def update_background_image(self):
    
        # 👇 Sube tres niveles si estás dentro de /PGP/pgp/ui/ChatWindow.py
        PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        fondo_path = os.path.join(PROJECT_ROOT, "pgp","assets", "images", "cyber-security-3400657_1280.jpg")

        fondo_pixmap = QPixmap(fondo_path)
        if fondo_pixmap.isNull():
            print(f"❌ Imagen no encontrada: {fondo_path}")
            return

        target_size = self.size()

        scaled_pixmap = fondo_pixmap.scaled(
            target_size,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )

        # Centrar la imagen dentro del widget
        x = (target_size.width() - scaled_pixmap.width()) // 2
        y = (target_size.height() - scaled_pixmap.height()) // 2

        transparent_pixmap = QPixmap(target_size)
        transparent_pixmap.fill(Qt.transparent)

        painter = QPainter(transparent_pixmap)
        painter.setOpacity(0.25)  # puedes reducir aún más si deseas
        painter.drawPixmap(x, y, scaled_pixmap)
        painter.end()

        self.background_label.setPixmap(transparent_pixmap)
        self.background_label.setGeometry(0, 0, target_size.width(), target_size.height())

        transparent_pixmap = QPixmap(scaled_pixmap.size())
        transparent_pixmap.fill(Qt.transparent)

        painter = QPainter(transparent_pixmap)
        painter.setOpacity(0.25)
        painter.drawPixmap(0, 0, scaled_pixmap)
        painter.end()

        self.background_label.setPixmap(transparent_pixmap)
        self.background_label.setGeometry(0, 0, self.width(), self.height())

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_background_image()
