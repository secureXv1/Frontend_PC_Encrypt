# ui/panels/tunnel_panel.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QHBoxLayout,
    QFileDialog, QMessageBox, QScrollArea, QFrame
)
from PyQt5.QtCore import Qt, QTimer
import base64, json
from tunnel_client import TunnelClient
from db_cliente import obtener_tunel_por_nombre
from password_utils import verificar_password

class TunnelCard(QFrame):
    def __init__(self, nombre, on_click):
        super().__init__()
        self.setStyleSheet("""
            QFrame {
                background-color: #232323;
                border-radius: 10px;
                padding: 10px;
            }
            QFrame:hover {
                background-color: #2f2f2f;
            }
        """)
        self.setCursor(Qt.PointingHandCursor)
        layout = QHBoxLayout(self)
        self.label = QLabel(f"🛡 {nombre}")
        self.label.setStyleSheet("font-weight: bold; color: white;")
        layout.addWidget(self.label)
        self.mousePressEvent = lambda event: on_click()

class TunnelPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent
        self.cliente = None

        main_layout = QHBoxLayout(self)

        # Panel izquierdo (tipo contactos)
        left_panel = QVBoxLayout()
        self.input_name = QLineEdit()
        self.input_name.setPlaceholderText("Nombre del túnel")
        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.Password)
        self.input_password.setPlaceholderText("Contraseña")
        self.input_alias = QLineEdit()
        self.input_alias.setPlaceholderText("Tu alias")

        self.btn_create = QPushButton("➕ Crear Túnel")
        self.btn_create.clicked.connect(self.crear_tunel_desde_ui)

        left_panel.addWidget(QLabel("🔐 Túneles Disponibles"))
        left_panel.addWidget(self.input_name)
        left_panel.addWidget(self.input_password)
        left_panel.addWidget(self.input_alias)
        left_panel.addWidget(self.btn_create)

        # Scroll para túneles
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_widget)

        left_panel.addWidget(self.scroll_area)
        main_layout.addLayout(left_panel, 2)

        # Panel derecho (chat)
        right_panel = QVBoxLayout()
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Escribe un mensaje...")
        self.btn_send = QPushButton("Enviar")
        self.btn_send.clicked.connect(self.enviar_mensaje)

        input_layout = QHBoxLayout()
        input_layout.addWidget(self.chat_input)
        input_layout.addWidget(self.btn_send)

        right_panel.addWidget(QLabel("💬 Chat del Túnel"))
        right_panel.addWidget(self.chat_area)
        right_panel.addLayout(input_layout)
        main_layout.addLayout(right_panel, 4)

        self.chat_area.hide()
        self.chat_input.hide()
        self.btn_send.hide()

        self.actualizar_lista_tuneles()

    def crear_tunel_desde_ui(self):
        import requests
        nombre = self.input_name.text().strip()
        clave = self.input_password.text().strip()
        if not nombre or not clave:
            QMessageBox.warning(self, "Error", "Nombre y contraseña requeridos")
            return
        try:
            response = requests.post("http://symbolsaps.ddns.net:8000/api/tunnels/create", json={
                "name": nombre,
                "password": clave
            })
            if response.status_code == 201:
                self.chat_area.append(f"🔐 Túnel '{nombre}' creado exitosamente.")
                self.actualizar_lista_tuneles()
            else:
                raise Exception(response.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo crear el túnel:\n{e}")

    def actualizar_lista_tuneles(self):
        import requests
        self.scroll_clear()
        try:
            response = requests.get("http://symbolsaps.ddns.net:8000/api/tunnels")
            if response.status_code == 200:
                tuneles = response.json()
                for tunel in tuneles:
                    card = TunnelCard(tunel["name"], lambda t=tunel: self.unirse_a_tunel(t))
                    self.scroll_layout.addWidget(card)
            else:
                raise Exception("No se pudo obtener la lista de túneles")
        except Exception as e:
            self.chat_area.append(f"⚠️ Error cargando túneles: {e}")

    def scroll_clear(self):
        for i in reversed(range(self.scroll_layout.count())):
            widget = self.scroll_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def unirse_a_tunel(self, tunel):
        alias = self.input_alias.text().strip()
        if not alias:
            QMessageBox.warning(self, "Alias requerido", "Debes ingresar tu alias antes de conectarte.")
            return
        if not verificar_password(self.input_password.text().strip(), tunel["password_hash"]):
            QMessageBox.warning(self, "Error", "Contraseña incorrecta")
            return
        try:
            self.cliente = TunnelClient(
                host="symbolsaps.ddns.net",
                port=5050,
                tunnel_id=tunel["id"],
                alias=alias,
                on_receive_callback=self.recibir_mensaje
            )
            self.cliente.connect()
            self.chat_area.show()
            self.chat_input.show()
            self.btn_send.show()
            self.chat_area.append(f"✅ Conectado a '{tunel['name']}' como {alias}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error de conexión:\n{e}")

    def enviar_mensaje(self):
        mensaje = self.chat_input.text().strip()
        if mensaje and self.cliente:
            try:
                payload = {
                    "type": "text",
                    "from": self.input_alias.text(),
                    "text": mensaje,
                }
                self.cliente.send(json.dumps(payload) + "\n")
                self.chat_area.append(f"🧑 Tú: {mensaje}")
                self.chat_input.clear()
            except Exception as e:
                self.chat_area.append(f"⚠️ Error al enviar el mensaje: {e}")

    def recibir_mensaje(self, mensaje):
        try:
            data = json.loads(mensaje)
            tipo = data.get("type", "text")
            remitente = data.get("from", "Desconocido")

            if tipo == "text":
                self.chat_area.append(f"{remitente}: {data.get('text', '')}")

            elif tipo == "file":
                nombre = data.get("filename", "archivo")
                b64_data = data.get("data", "")
                self.chat_area.append(f"{remitente} envió un archivo: {nombre} 📎")

                def guardar():
                    ruta, _ = QFileDialog.getSaveFileName(self, "Guardar archivo", nombre)
                    if ruta:
                        with open(ruta, "wb") as f:
                            f.write(base64.b64decode(b64_data))
                        self.chat_area.append(f"✅ Guardado en: {ruta}")
                QTimer.singleShot(0, guardar)
        except Exception as e:
            self.chat_area.append(f"⚠️ Mensaje inválido: {mensaje}")
