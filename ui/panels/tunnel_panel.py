from PyQt5.QtWidgets import ( QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QHBoxLayout,
QFileDialog, QMessageBox, QScrollArea, QFrame, QSpacerItem, QSizePolicy, QDialog, QFormLayout, QListWidget, QListWidgetItem)
from PyQt5.QtCore import (
    Qt,
    QTimer,
    QPropertyAnimation,
    QVariantAnimation,
    pyqtProperty,
    pyqtSignal,
    QUrl,
)
from PyQt5.QtGui import QColor, QPalette, QIcon, QPixmap, QPainter, QFont
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtMultimedia import QSoundEffect
import base64, json
from tunnel_client import TunnelClient
from db_cliente import obtener_tunel_por_nombre, get_client_uuid, obtener_ultimas_conexiones_por_tunel, obtener_tuneles_desde_backend
from password_utils import verificar_password
from chat_window import ChatWindow
import requests
import os
from datetime import datetime

def formatear_timestamp(timestamp_ms):
    try:
        dt = datetime.fromtimestamp(timestamp_ms / 1000)
        return dt.strftime("%d/%m/%Y %H:%M")
    except:
        return "Fecha inválida"


def colored_icon(svg_path, color, size=20):
    renderer = QSvgRenderer(svg_path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()

    return QIcon(pixmap)


class TunnelCard(QFrame):
    def __init__(self, nombre, on_click, conectado=False):
        super().__init__()
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedHeight(50)

        # Layout horizontal: borde izquierdo + contenido
        outer_layout = QHBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Borde izquierdo como línea visual
        self.borde = QFrame()
        self.borde.setFixedWidth(4)
        self.borde.setStyleSheet(
            f"background-color: {'#00BCD4' if conectado else '#444'};"
        )
        outer_layout.addWidget(self.borde)

        # Contenido real de la tarjeta
        wrapper = QFrame()
        wrapper.setStyleSheet("background-color: #1f1f1f;")
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(8, 4, 8, 4)
        wrapper_layout.setSpacing(2)

        # Título e ícono de conexión
        title_layout = QHBoxLayout()
        self.title = QLabel(nombre)
        self.title.setStyleSheet("font-size: 13px; color: white;")
        self.title.setTextInteractionFlags(Qt.NoTextInteraction)
        title_layout.addWidget(self.title)

        icon = QLabel("🟢" if conectado else "⚪")
        icon.setStyleSheet(f"""
            font-size: 14px;
            margin-left: 4px;
            color: {"#00ff00" if conectado else "#888"};
        """)
        title_layout.addStretch()
        title_layout.addWidget(icon)


        wrapper_layout.addLayout(title_layout)

        # Subtítulo
        self.subtitle = QLabel("Fecha de creación")
        self.subtitle.setStyleSheet("font-size: 10px; color: gray;")
        self.subtitle.setTextInteractionFlags(Qt.NoTextInteraction)
        wrapper_layout.addWidget(self.subtitle)

        outer_layout.addWidget(wrapper)

        # Animación de fondo al hacer clic
        self.mousePressEvent = lambda event: self._click_animation(on_click)

    def _click_animation(self, callback):
        anim = QVariantAnimation(
            startValue=QColor("#00BCD4"),
            endValue=QColor("#1f1f1f"),
            duration=200
        )
        anim.valueChanged.connect(self._update_background)
        anim.finished.connect(callback)
        anim.start()
        self._anim = anim

    def _update_background(self, color):
        self.setStyleSheet(f"background-color: {color.name()};")

    def set_conectado(self, conectado: bool):
        # Cambiar el color del borde izquierdo
        self.borde.setStyleSheet(
            f"background-color: {'#00BCD4' if conectado else '#444'};"
        )

        # Buscar el ícono dentro del layout y cambiar su texto y color
        wrapper = self.layout().itemAt(1).widget()  # index 1 = wrapper (después del borde)
        if isinstance(wrapper, QFrame):
            vlayout = wrapper.layout()
            if vlayout is not None:
                for i in range(vlayout.count()):
                    item = vlayout.itemAt(i)
                    if isinstance(item, QHBoxLayout):  # primera línea: nombre + ícono
                        for j in range(item.count()):
                            widget = item.itemAt(j).widget()
                            if isinstance(widget, QLabel) and widget.text() in ["🟢", "⚪"]:
                                widget.setText("🟢" if conectado else "⚪")
                                widget.setStyleSheet(f"""
                                    font-size: 14px;
                                    margin-left: 4px;
                                    color: {"#00ff00" if conectado else "#888"};
                                """)

class TunnelPanel(QWidget):
    """Panel principal para gestionar y mostrar los túneles."""

    # Signal para procesar mensajes en el hilo de la interfaz
    message_received = pyqtSignal(str)
    def __init__(self, uuid, hostname, sistema, parent=None):
        super().__init__(parent)
        self.uuid = uuid
        self.hostname = hostname
        self.sistema = sistema
        self.parent = parent
        self.conexiones_tuneles = {}
        self.participants = {}
        self.files = {}
        self.cliente = None

        self.tunnel_cards = {}
        self.tuneles_list = QListWidget()
        self.tuneles_list.setStyleSheet("""
            QListWidget {
                background-color: #2b2b2b;
                color: white;
                border: none;
                padding: 10px;
            }
            QListWidget::item {
                padding: 12px 10px;
                border-bottom: 1px solid #444;
                font-size: 14px;
            }
            QListWidget::item:selected {
                background-color: #444;
                color: #00bfff;
            }
        """)
        self.tuneles_list.setFixedWidth(300)
        self.tuneles = []

        # Conectar la señal que procesa mensajes entrantes en el hilo de Qt
        self.message_received.connect(self._handle_incoming_message)

        from db_cliente import get_client_uuid
        _ = get_client_uuid()  # 👈 Esto asegura que se registre el cliente

        main_layout = QHBoxLayout(self)

        # ==== PANEL IZQUIERDO (Túneles) ====
        self.left_panel = QVBoxLayout()
        self.left_panel.setSpacing(10)

        search_layout = QHBoxLayout()

        search_input = QLineEdit()
        search_input.setPlaceholderText("Buscar túnel")
        search_input.setStyleSheet("padding: 4px; background-color: #222; border: none; color: white;")
        search_layout.addWidget(search_input)

        # Botón +
        btn_mas = QPushButton("＋")
        btn_mas.setFixedWidth(50)
        btn_mas.setStyleSheet("color: #00BCD4; font-size: 18px; background-color: #333; border: none;")
        btn_mas.setCursor(Qt.PointingHandCursor)
        search_layout.addWidget(btn_mas)

        # Conectar la acción del botón
        btn_mas.clicked.connect(self.mostrar_menu_tunel)

        self.left_panel.addLayout(search_layout)

        self.scroll_area = QScrollArea()
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setFixedWidth(320)
        self.scroll_area.setWidgetResizable(True)
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_layout.addWidget(self.tuneles_list)
        self.scroll_area.setWidget(self.scroll_widget)
        self.left_panel.addWidget(self.scroll_area)

        left_container = QWidget()
        left_container.setLayout(self.left_panel)
        left_container.setFixedWidth(340)
        main_layout.addWidget(left_container)

        # ==== PANEL CENTRAL (Chat) ====
        from PyQt5.QtWidgets import QTabWidget

        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.cerrar_pestana_tunel)
        self.tab_widget.currentChanged.connect(self._tab_changed)
        main_layout.addWidget(self.tab_widget, 4)

        # Timer para refrescar participantes automáticamente
        self.participant_timer = QTimer(self)
        self.participant_timer.timeout.connect(self._actualizar_participantes_periodicamente)
        self.participant_timer.setInterval(8000)  # 8000 ms = 8 segundos
        self.participant_timer.start()

        # ==== PANEL DERECHO (Participantes y Archivos) ====
        right_panel = QVBoxLayout()

        label_participantes = QLabel("Participantes")
        label_participantes.setStyleSheet("background: transparent; color: white; font-weight: bold;")
        right_panel.addWidget(label_participantes)

        self.users_list = QListWidget()
        self.users_list.setStyleSheet("""
            QListWidget {
                background-color: #2b2b2b;
                color: white;
                border: none;
                padding: 10px;
            }
            QListWidget::item {
                padding: 12px 10px;
                border-bottom: 1px solid #444;
                font-size: 14px;
            }
            QListWidget::item:selected {
                background-color: #444;
                color: #00bfff;
            }
        """)
        self.users_list.setFixedWidth(275)
        right_panel.addWidget(self.users_list)

        label_archivos = QLabel("Archivos")
        label_archivos.setStyleSheet("background: transparent; color: white; font-weight: bold;")
        right_panel.addWidget(label_archivos)

        self.files_list = QListWidget()
        self.files_list.setFixedWidth(275)
        self.files_list.setStyleSheet("background-color: #000; color: white;")
        # Descargar el archivo con un solo clic
        self.files_list.itemClicked.connect(self._download_file_from_list)
        right_panel.addWidget(self.files_list)

        right_container = QWidget()
        right_container.setLayout(right_panel)
        right_container.setFixedWidth(300)
        main_layout.addWidget(right_container)

        self.sound_join = QSoundEffect()
        self.sound_join.setSource(QUrl.fromLocalFile(os.path.abspath("assets/sounds/join.wav")))
        self.sound_join.setVolume(0.7)  # Volumen opcional entre 0.0 y 1.0

        self.sound_leave = QSoundEffect()
        self.sound_leave.setSource(QUrl.fromLocalFile(os.path.abspath("assets/sounds/leave.wav")))
        self.sound_leave.setVolume(0.7)

        self.actualizar_lista_tuneles()

    # FUNCIONES!!!!

    def crear_tunel_desde_ui(self):
        import requests
        nombre = self.input_name.text().strip().upper()
        clave = self.input_password.text().strip()
        if not nombre or not clave:
            QMessageBox.warning(self, "Error", "Nombre y contraseña requeridos")
            return
        try:
            from db_cliente import get_client_uuid
            uuid = get_client_uuid()

            response = requests.post("http://symbolsaps.ddns.net:8000/api/tunnels/create", json={
                "name": nombre,
                "password": clave,
                "uuid": uuid  # 👈 necesario para que el backend lo reciba
            })

            if response.status_code == 201:
                QMessageBox.information(self, "Túnel creado", f"🔐 Túnel '{nombre}' creado exitosamente.")
                self.actualizar_lista_tuneles()
            else:
                raise Exception(response.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo crear el túnel:\n{e}")

    def formatear_timestamp(ts):
        if not ts or ts == 0:
            return "sin conexión"
        return datetime.fromtimestamp(ts / 1000).strftime("%d %b %Y %H:%M")

    def actualizar_lista_tuneles(self):
        self.tuneles_list.clear()
        uuid_actual = get_client_uuid()
        print(f"🧠 UUID actual: {uuid_actual}")

        try:
            datos = obtener_tuneles_desde_backend(uuid_actual)
            mis_tuneles = datos.get("mis_tuneles", [])
            recientes = datos.get("conexiones_recientes", [])

            print(f"🔐 Túneles creados por mí: {len(mis_tuneles)}")
            print(f"📡 Túneles recientes: {len(recientes)}")

            # 🧱 Encabezado: MIS TÚNELES
            titulo_mis = QListWidgetItem("🔐 MIS TÚNELES")
            titulo_mis.setFlags(Qt.NoItemFlags)
            titulo_mis.setForeground(QColor("#999999"))
            titulo_mis.setFont(QFont("Arial", 11, QFont.Bold))
            self.tuneles_list.addItem(titulo_mis)

            for t in mis_tuneles:
                conectado = t.get('id') in self.conexiones_tuneles
                card = TunnelCard(
                    nombre=t['name'],
                    on_click=lambda t=t: self.abrir_tunel(t),
                    conectado=conectado
                )
                item = QListWidgetItem()
                item.setSizeHint(card.sizeHint())
                self.tuneles_list.addItem(item)
                self.tuneles_list.setItemWidget(item, card)
                self.tunnel_cards[t['id']] = card
                print(f"➕ Agregando túnel propio (visual): {t['name']}")

            # 🛰 Encabezado: CONEXIONES RECIENTES
            titulo_recientes = QListWidgetItem("📡 CONEXIONES RECIENTES")
            titulo_recientes.setFlags(Qt.NoItemFlags)
            titulo_recientes.setForeground(QColor("#999999"))
            titulo_recientes.setFont(QFont("Arial", 11, QFont.Bold))
            self.tuneles_list.addItem(titulo_recientes)

            for t in recientes:
                conectado = t.get('id') in self.conexiones_tuneles
                card = TunnelCard(
                    nombre=t['name'],
                    on_click=lambda t=t: self.abrir_tunel(t),
                    conectado=conectado
                )
                item = QListWidgetItem()
                item.setSizeHint(card.sizeHint())
                self.tuneles_list.addItem(item)
                self.tuneles_list.setItemWidget(item, card)
                self.tunnel_cards[t['id']] = card
                print(f"➕ Agregando túnel reciente (visual): {t['name']}")

        except Exception as e:
            print(f"❌ Error al cargar túneles: {e}")


    def scroll_clear(self):
        for i in reversed(range(self.scroll_layout.count())):
            widget = self.scroll_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def abrir_tunel(self, tunel):
        """Compatibilidad con versiones anteriores."""
        self.unirse_a_tunel(tunel)

    def unirse_a_tunel(self, tunel):
        from PyQt5.QtWidgets import QMessageBox
        from PyQt5.QtCore import Qt

        tunnel_id = tunel["id"]
        if tunnel_id in self.conexiones_tuneles:
            msg = QMessageBox(self)
            msg.setWindowTitle("Ya conectado")
            msg.setIcon(QMessageBox.Information)
            msg.setTextFormat(Qt.PlainText)
            msg.setText(
                f"⚠️ Ya estás conectado al túnel:\n\n'{tunel['name']}'\ncomo alias: {self.conexiones_tuneles[tunnel_id]['alias']}"
            )

            # 🔧 Estilo para fondo oscuro y texto blanco
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #2e2e2e;
                }
                QLabel {
                    color: white;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #444;
                    color: white;
                    padding: 6px 12px;
                    min-width: 60px;
                }
                QPushButton:hover {
                    background-color: #666;
                }
            """)

            # ✅ Forzar tamaño mínimo
            msg.setMinimumWidth(360)
            msg.setMinimumHeight(180)

            msg.exec_()
            return

        from PyQt5.QtWidgets import QDialog, QFormLayout

        dialog = QDialog(self)
        dialog.setWindowTitle("Conectarse al túnel")
        layout = QFormLayout(dialog)

        input_alias = QLineEdit()
        input_alias.setStyleSheet("text-transform: uppercase; color: white;")
        input_alias.textChanged.connect(lambda text: input_alias.setText(text.upper()))
        input_password = QLineEdit()
        input_password.setEchoMode(QLineEdit.Password)

        layout.addRow("Alias:", input_alias)
        layout.addRow("Contraseña:", input_password)

        btn_ok = QPushButton("Conectar")
        btn_ok.clicked.connect(dialog.accept)
        layout.addWidget(btn_ok)

        if not dialog.exec_():
            return

        alias = input_alias.text().strip().upper()
        password = input_password.text().strip()

        if not alias or not password:
            QMessageBox.warning(self, "Error", "Alias y contraseña son requeridos")
            return

        import requests
        try:
            response = requests.post("http://symbolsaps.ddns.net:8000/api/tunnels/join", json={
                "tunnel_id": tunel["id"],
                "password": password,
                "alias": alias
            })
            if response.status_code != 200:
                raise Exception(response.text)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Validación fallida:\n{e}")
            return

        try:
            nombre = tunel["name"]  # ✅ Aquí se define

            from db_cliente import get_client_uuid, registrar_alias_cliente
            uuid = get_client_uuid()

            self.cliente = TunnelClient(
                host="symbolsaps.ddns.net",
                port=5050,
                tunnel_id=tunel["id"],
                alias=alias,
                uuid=uuid,  # ✅ Aquí se pasa el uuid requerido
                on_receive_callback=self.recibir_mensaje
            )

            self.cliente.connect()
            registrar_alias_cliente(uuid, tunel["id"], alias)

            tab = QWidget()
            layout = QVBoxLayout(tab)

            header_layout = QHBoxLayout()
            label = QLabel(f"🟢 {nombre} como {alias}")
            label.setStyleSheet("color: white; font-weight: bold;")
            btn_close = QPushButton("Desconectar")
            btn_close.setStyleSheet("background-color: red; color: white; padding: 2px;")
            btn_close.clicked.connect(lambda: self.desconectar_tunel(tab, tunel['id']))
            header_layout.addWidget(label)
            header_layout.addStretch()
            header_layout.addWidget(btn_close)

            from chat_window import ChatWindow
            chat_window = ChatWindow(
                alias=alias,
                client=self.cliente,
                tunnel_id=tunel["id"],
                uuid=uuid,
                on_file_event=self.handle_file_event,
                 on_receive_callback=self.recibir_mensaje
            )

            layout.addLayout(header_layout)
            layout.addWidget(chat_window)

            self.tab_widget.addTab(tab, nombre)
            self.participant_timer.start()
            self.tab_widget.setCurrentWidget(tab)

            self.conexiones_tuneles[tunel["id"]] = {
                "cliente": self.cliente,
                "chat": chat_window,
                "tab": tab,
                "alias": alias,
            }

            card = self.tunnel_cards.get(tunel["id"])
            if card:
                card.set_conectado(True)

            self.fetch_participants(tunel["id"])
            self.fetch_files(tunel["id"])
            self.update_side_lists(tunel["id"])
            self.actualizar_lista_tuneles()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error de conexión:\n{e}")

    def recibir_mensaje(self, mensaje):
        """Callback del cliente de túnel (hilo de red)."""
        # Redirigir el procesamiento al hilo principal a través de una señal
        self.message_received.emit(mensaje)

    def _handle_incoming_message(self, mensaje):
        """Procesa ``mensaje`` en el hilo principal de Qt."""
        try:
            print("📦 Mensaje recibido bruto:", repr(mensaje))

            if mensaje.strip() == "OK":
                print("ℹ️ Mensaje de confirmación recibido. Ignorado.")
                return

            data = json.loads(mensaje)
            tunel_id = data.get("tunnel_id")

            if tunel_id not in self.conexiones_tuneles:
                print("⚠️ Mensaje recibido de túnel desconocido")
                return

            # ⚠️ Si viene campo "contenido", decodifícalo
            if "contenido" in data:
                contenido_str = data["contenido"]
                try:
                    contenido_dict = json.loads(contenido_str)
                    print("📨 Contenido decodificado:", contenido_dict)
                    mensaje = json.dumps(contenido_dict)  # lo pasamos como string JSON otra vez
                except Exception as e:
                    print("❌ Error al decodificar 'contenido':", e)
                    return

            chat = self.conexiones_tuneles[tunel_id]["chat"]
            chat.procesar_mensaje(mensaje)

        except Exception as e:
            print("⚠️ Error al procesar mensaje:", e)

    def mostrar_menu_tunel(self):
        from PyQt5.QtWidgets import QMenu, QAction

        menu = QMenu(self)

        accion_crear = QAction("➕ Crear túnel", self)
        accion_conectar = QAction("🔗 Conectarse a túnel", self)

        accion_crear.triggered.connect(self.mostrar_dialogo_crear_tunel)
        accion_conectar.triggered.connect(self.mostrar_dialogo_conectar_tunel)

        menu.addAction(accion_crear)
        menu.addAction(accion_conectar)

        # Mostrar menú debajo del botón
        cursor_pos = self.mapFromGlobal(self.cursor().pos())
        menu.exec_(self.mapToGlobal(cursor_pos))

    def mostrar_dialogo_crear_tunel(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Crear túnel")
        layout = QFormLayout(dialog)

        self.input_name = QLineEdit()
        self.input_name.setStyleSheet("text-transform: uppercase; color: white;")
        self.input_name.textChanged.connect(lambda text: self.input_name.setText(text.upper()))

        self.input_password = QLineEdit()
        self.input_password.setEchoMode(QLineEdit.Password)
        self.input_password.setStyleSheet("color: white;")
        self.input_password.setEchoMode(QLineEdit.Password)

        layout.addRow("Nombre:", self.input_name)
        layout.addRow("Contraseña:", self.input_password)

        btn_ok = QPushButton("Crear")
        btn_ok.clicked.connect(lambda: [dialog.accept(), self.crear_tunel_desde_ui()])
        layout.addWidget(btn_ok)

        dialog.exec_()

    def mostrar_dialogo_conectar_tunel(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Conectarse a túnel")
        layout = QFormLayout(dialog)

        input_nombre = QLineEdit()
        input_nombre.setStyleSheet("text-transform: uppercase; color: white;")
        input_nombre.textChanged.connect(lambda text: input_nombre.setText(text.upper()))

        input_alias = QLineEdit()
        input_alias.setStyleSheet("text-transform: uppercase; color: white;")
        input_alias.textChanged.connect(lambda text: input_alias.setText(text.upper()))

        input_password = QLineEdit()
        input_password.setEchoMode(QLineEdit.Password)

        layout.addRow("Nombre del túnel:", input_nombre)
        layout.addRow("Alias:", input_alias)
        layout.addRow("Contraseña:", input_password)

        btn_ok = QPushButton("Conectar")
        layout.addWidget(btn_ok)

        btn_ok.clicked.connect(lambda: self._conectar_a_tunel_manual(
            dialog, input_nombre.text().strip().upper(),
            input_alias.text().strip().upper(),
            input_password.text().strip()
        ))

        dialog.exec_()

    def _conectar_a_tunel_manual(self, dialog, nombre, alias, password):
        tunnel_id = tunel["id"]
        # ✅ Verificar si ya estás conectado a este túnel
        if tunnel_id in self.conexiones_tuneles:
            msg = QMessageBox(self)
            msg.setWindowTitle("Ya conectado")
            msg.setText(f"⚠️ Ya estás conectado al túnel '{tunel['name']}' con el alias: {self.conexiones_tuneles[tunnel_id]['alias']}")
            msg.setIcon(QMessageBox.Information)
            
            # 🔧 Estilo para tema oscuro
            msg.setStyleSheet("""
                QMessageBox {
                    background-color: #2e2e2e;
                    color: white;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #444;
                    color: white;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #666;
                }
            """)
            msg.exec_()
            return

        import requests
        if not nombre or not alias or not password:
            QMessageBox.warning(self, "Error", "Todos los campos son requeridos")
            return

        try:
            response = requests.get("http://symbolsaps.ddns.net:8000/api/tunnels")
            if response.status_code != 200:
                raise Exception("Error al consultar túneles")

            tuneles = response.json()
            tunel = next((t for t in tuneles if t["name"] == nombre), None)
            if not tunel:
                raise Exception("Túnel no encontrado")

            join_resp = requests.post("http://symbolsaps.ddns.net:8000/api/tunnels/join", json={
                "tunnel_id": tunel["id"],
                "password": password,
                "alias": alias
            })
            if join_resp.status_code != 200:
                raise Exception(join_resp.text)
            
            nombre = tunel["name"]
            from db_cliente import get_client_uuid, registrar_alias_cliente
            uuid = get_client_uuid()

            self.cliente = TunnelClient(
                host="symbolsaps.ddns.net",
                port=5050,
                tunnel_id=tunel["id"],
                alias=alias,
                uuid=uuid,  # ✅ Aquí se pasa el uuid requerido
                on_receive_callback=self.recibir_mensaje
            )

            self.cliente.connect()
            registrar_alias_cliente(uuid, tunel["id"], alias)

            # Crear la pestaña visual del chat
            tab = QWidget()
            layout = QVBoxLayout(tab)

            header_layout = QHBoxLayout()
            label = QLabel(f"🟢 {nombre} como {alias}")
            label.setStyleSheet("color: white; font-weight: bold;")
            btn_close = QPushButton("Desconectar")
            btn_close.setStyleSheet("background-color: red; color: white; padding: 2px;")
            btn_close.clicked.connect(lambda: self.desconectar_tunel(tab, tunel['id']))
            header_layout.addWidget(label)
            header_layout.addStretch()
            header_layout.addWidget(btn_close)

            from chat_window import ChatWindow
            chat_window = ChatWindow(
                alias=alias,
                client=self.cliente,
                tunnel_id=tunel["id"],
                uuid=uuid,
                on_file_event=self.handle_file_event,
                 on_receive_callback=self.recibir_mensaje
            )

            layout.addLayout(header_layout)
            layout.addWidget(chat_window)

            self.tab_widget.addTab(tab, nombre)
            self.participant_timer.start()
            self.tab_widget.setCurrentWidget(tab)

            self.conexiones_tuneles[tunel["id"]] = {
                "cliente": self.cliente,
                "chat": chat_window,
                "chat_area": chat_window.chat_area,  # compatibilidad
                "tab": tab,
                "alias": alias,
            }

            card = self.tunnel_cards.get(tunel["id"])
            if card:
                card.set_conectado(True)

            self.fetch_participants(tunel["id"])
            self.fetch_files(tunel["id"])
            self.update_side_lists(tunel["id"])
            self.actualizar_lista_tuneles()

            dialog.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def desconectar_tunel(self, tab, tunel_id):
        if tunel_id in self.conexiones_tuneles:
            cliente = self.conexiones_tuneles[tunel_id]["cliente"]
            try:
                cliente.socket.close()
            except:
                pass

            # Notificar al backend que el cliente se desconectó
            try:
                import requests
                requests.post("http://symbolsaps.ddns.net:8000/api/tunnels/disconnect", json={
                    "uuid": self.uuid,
                    "tunnel_id": tunel_id
                })
            except Exception as e:
                print("⚠️ Error notificando desconexión:", e)

            del self.conexiones_tuneles[tunel_id]
            self.participants.pop(tunel_id, None)
            self.files.pop(tunel_id, None)

        idx = self.tab_widget.indexOf(tab)
        if idx >= 0:
            self.tab_widget.removeTab(idx)

        if not self.tab_widget.count():
            self.users_list.clear()
            self.files_list.clear()
            self.participant_timer.stop()

        card = self.tunnel_cards.get(tunel_id)
        if card:
            card.set_conectado(False)

    def cerrar_pestana_tunel(self, index):
        tab = self.tab_widget.widget(index)
        for tunel_id, data in self.conexiones_tuneles.items():
            if data.get("tab") == tab:
                self.desconectar_tunel(tab, tunel_id)
                break

    def enviar_mensaje_tunel(self, tunel_id, mensaje, chat_area, input_field):
        if not mensaje.strip():
            return

        if tunel_id not in self.conexiones_tuneles:
            QMessageBox.warning(self, "Error", "Túnel no encontrado")
            return

        cliente = self.conexiones_tuneles[tunel_id]["cliente"]
        try:
            cliente.socket.sendall(mensaje.encode())
            chat_area.append(f"{mensaje}")
            input_field.clear()
        except Exception as e:
            chat_area.append(f"⚠️ Error al enviar mensaje: {e}")

    # ---- Gestión de participantes y archivos ----
    def current_tunnel_id(self):
        tab = self.tab_widget.currentWidget()
        for tid, data in self.conexiones_tuneles.items():
            if data.get("tab") == tab:
                return tid
        return None

    def _tab_changed(self, index):
        tid = self.current_tunnel_id()
        if tid:
            self.update_side_lists(tid)

    def fetch_participants(self, tunnel_id):
        """Llena ``self.participants`` con la lista de participantes reales para ``tunnel_id``."""
        import requests, time
        current_alias = self.conexiones_tuneles.get(tunnel_id, {}).get("alias")
        participantes = []

        try:
            resp = requests.get(f"http://symbolsaps.ddns.net:8000/api/tunnels/{tunnel_id}/participants")
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    participantes = data.get("participants") or data.get("data") or list(data)
                else:
                    participantes = data
        except Exception as e:
            print("⚠️ Error obteniendo participantes:", e)

        if not isinstance(participantes, list):
            participantes = [participantes]

        # Añadir nuestro propio alias si no está en la lista de aliases de nadie
        if current_alias:
            encontrado = any(
                current_alias in p.get("aliases", [])
                for p in participantes if isinstance(p, dict)
            )
            if not encontrado:
                participantes.append({
                    "aliases": [current_alias],
                    "client_uuid": self.uuid,
                    "hostname": self.hostname,
                    "ultimo_acceso": int(time.time() * 1000)
                })

        self.participants[tunnel_id] = participantes

    def fetch_files(self, tunnel_id):
        import requests
        try:
            resp = requests.get(f"http://symbolsaps.ddns.net:8000/api/tunnels/{tunnel_id}/files")
            if resp.status_code == 200:
                self.files[tunnel_id] = resp.json()
            else:
                self.files[tunnel_id] = []
        except Exception as e:
            print("⚠️ Error obteniendo archivos:", e)
            self.files[tunnel_id] = []

    def update_side_lists(self, tunnel_id):
        self.users_list.clear()
        for usuario in self.participants.get(tunnel_id, []):
            if isinstance(usuario, dict):
                alias_list = usuario.get("aliases", [])
                alias = alias_list[0] if alias_list else "Sin alias"
            else:
                alias = str(usuario)

            current_alias = self.conexiones_tuneles.get(tunnel_id, {}).get("alias")
            if alias == current_alias:
                alias = f"{alias} (tú)"

            self.users_list.addItem(alias)

        self.files_list.clear()
        for archivo in self.files.get(tunnel_id, []):
            nombre = archivo.get("filename") if isinstance(archivo, dict) else archivo
            item = QListWidgetItem(nombre)
            icon_pixmap = QPixmap("assets/icons/file.svg").scaled(48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            item.setIcon(QIcon(icon_pixmap))
            item.setData(Qt.UserRole, archivo)
            self.files_list.addItem(item)

    def handle_file_event(self, tunnel_id, nombre, url):
        entry = {"filename": nombre, "url": url}
        self.files.setdefault(tunnel_id, []).append(entry)
        if self.current_tunnel_id() == tunnel_id:
            item = QListWidgetItem(nombre)
            icon_pixmap = QPixmap("assets/icons/file.svg").scaled(48, 48, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            item.setIcon(QIcon(icon_pixmap))
            item.setData(Qt.UserRole, entry)
            self.files_list.addItem(item)

    def _download_file_from_list(self, item):
        info = item.data(Qt.UserRole)
        if not isinstance(info, dict):
            return
        url = info.get("url")
        nombre = info.get("filename") or info.get("name")
        tid = self.current_tunnel_id()
        if tid and tid in self.conexiones_tuneles:
            chat = self.conexiones_tuneles[tid].get("chat")
            if chat:
                chat.download_file(url, nombre)

    def _actualizar_participantes_periodicamente(self):
        tid = self.current_tunnel_id()
        if not tid:
            return

        old_set = set()
        for u in self.participants.get(tid, []):
            if isinstance(u, dict):
                old_set.update(u.get("aliases", []))
            else:
                old_set.add(str(u))

        self.fetch_participants(tid)

        new_set = set()
        for u in self.participants.get(tid, []):
            if isinstance(u, dict):
                new_set.update(u.get("aliases", []))
            else:
                new_set.add(str(u))

        # Detectar cambios
        nuevos = new_set - old_set
        salientes = old_set - new_set

        if nuevos:
            print("🔔 Conectado:", nuevos)
            self.sound_join.play()

        if salientes:
            print("🔕 Desconectado:", salientes)
            self.sound_leave.play()

        self.update_side_lists(tid)

