import os
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QGroupBox, QGridLayout, QToolButton, QSizePolicy
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, json, os
from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import os, json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import threading
from chat_window import ChatWindow
from tunnel_client import TunnelClient
from password_utils import verificar_password
from db_cliente import crear_tunel, obtener_tunel_por_nombre, guardar_uuid_localmente, get_client_uuid, registrar_cliente
import platform, socket, uuid
import requests
import uuid
import socket
import platform
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QProgressBar, QPushButton, QScrollArea 
import re
from cryptography.hazmat.backends import default_backend
import hashlib
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import QInputDialog
from PyQt5.QtWidgets import QLabel, QHBoxLayout, QWidget
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QTimer, Qt, QSize, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt5.QtWidgets import QLabel
from PyQt5.QtGui import QIcon, QPixmap, QPainter, QImage, QColor
from PyQt5.QtWidgets import QComboBox
import json
import base64
from PyQt5.QtWidgets import QInputDialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtGui import QPainter, QImage, QDragEnterEvent, QDropEvent
from PyQt5.QtWidgets import QFileDialog, QMessageBox, QInputDialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import os, json, base64
from ui.password_dialog import PasswordDialog
from ui.crypto_utils import AESCBCWrapper
from ui.encryption_method_dialog import EncryptionMethodDialog
from db_cliente import get_client_uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



#Clase para garantizar copatibilidad multiplataforma
class AESGCMWrapper:
    def __init__(self, key: bytes):
        if len(key) not in [16, 24, 32]:
            raise ValueError("La clave AES debe tener 16, 24 o 32 bytes.")
        self.key = key

    def encrypt(self, data: bytes) -> tuple[bytes, bytes]:
        if isinstance(data, str):
            data = data.encode("utf-8")
        aesgcm = AESGCM(self.key)
        iv = os.urandom(12)
        encrypted = aesgcm.encrypt(iv, data, None)
        return iv, encrypted

    def decrypt(self, encrypted_data: bytes, iv: bytes) -> bytes:
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(iv, encrypted_data, None)





#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Clave pública maestra
PUBLIC_KEY_PEM = b"""-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAiCfktLjm9bcCMzIyGnKwZ4frVoBi2nHDuaaIsYPs3t4pL5l+Udq3
FO+lhKZtSCZZI54MLRqRamelnSHNpFxIUKiU34ZKiv6o+mPCtQegZ1EaoMEKOu26
MukDC2oFL9b5R17USZntZOGFfC8s2NPlA5zMfRheR49Ufb/4lLNGKoTql3ACzHqH
k05vcwQcR/isoHkWk3m4+r7HFDb4aMqjMj1N3DkKe2upeQIExdrcrBNKYZ8g/LpF
p2S13+C0Qlj/mvDiarJ3/c9+ekNhCnInSjFYmLLH1ZeowWeH+fZXSOAL0WIOvi+R
ynjvpT5BfnNGrJW9iP0QJgsw2axxOZw6GwIDAQAB
-----END RSA PUBLIC KEY-----"""

MASTER_PASSWORD = b'SeguraAdmin123!'
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#Clase Drag and Drop para añadir archivos
class FileDropWidget(QLabel):
    fileDropped = pyqtSignal(str)

    def __init__(self, placeholder_text="Arrastra un archivo aquí o haz clic para buscar...", parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setAlignment(Qt.AlignCenter)
        self.setWordWrap(True)

        self.placeholder_text = placeholder_text
        self.file_path = ""
        self.active_style = """
            QLabel {
                background-color: #2b2b2b;
                color: white;
                border: 2px solid #00BCD4;
                border-radius: 10px;
                padding: 20px;
                font-size: 13px;
            }
        """
        self.default_style = """
            QLabel {
                background-color: #2b2b2b;
                color: #aaa;
                border: 2px dashed #5a5a5a;
                border-radius: 10px;
                padding: 20px;
                font-size: 13px;
            }
            QLabel:hover {
                border-color: #00BCD4;
                color: white;
            }
        """
        self.setText(self.placeholder_text)
        self.setStyleSheet(self.default_style)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            self.set_file_path(file_path)
            self.fileDropped.emit(file_path)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", "Todos los archivos (*)")
            if file_path:
                self.set_file_path(file_path)
                self.fileDropped.emit(file_path)

    def set_file_path(self, path: str):
        self.file_path = path
        self.setText(f"<b>{os.path.basename(path)}</b>")
        self.setStyleSheet(self.active_style)






class EncryptionPanel(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Panel Cifrado")
        self.setStyleSheet("background-color: #1E1E1E;")  # Fondo oscuro coherente
        self.icon_path = "assets/icons"
        self.init_ui()
    
    #Método reutilizable para seleccionar archivos
    def browse_file(self, line_edit, file_filter="Todos los archivos (*)"):
        file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo", "", file_filter)
        if file_path:
            line_edit.setText(file_path)

    
    #Función para cambiar de color los iconos del menú (5 opciones)
    def load_colored_svg_icon(self, path, color_hex="#FFFFFF"):
        renderer = QSvgRenderer(path)
        image = QImage(36, 36, QImage.Format_ARGB32)
        image.fill(Qt.transparent)

        # Renderizar SVG
        painter = QPainter(image)
        renderer.render(painter)
        painter.end()

        # Aplicar color
        mask = image.createMaskFromColor(Qt.transparent, Qt.MaskOutColor)
        painter = QPainter(image)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(image.rect(), QColor(color_hex))
        painter.end()

        return QIcon(QPixmap.fromImage(image))

    
        
    #Función para mostrar menú + diseño
    def init_ui(self):
        self.setStyleSheet("background-color: #1E1E1E;")
        main_layout = QHBoxLayout(self)

        # Menú lateral
        self.menu_layout = QVBoxLayout()
        self.menu_layout.setSpacing(20)
        self.menu_layout.setContentsMargins(20, 30, 10, 30)
        self.menu_buttons = {}
        self.selected_button = None

        options = [
            ("Llaves", "keys.svg"),
            ("Notas", "notas.svg"),
            ("Cifrar", "encrypt.svg"),
            ("Descifrar", "decrypt.svg"),
            ("Ocultar", "hidden.svg"),
            ("Extraer", "extract.svg"),
        ]

        for label, icon_file in options:
            btn = QToolButton()
            btn.setText(label)
            icon_path = os.path.join(self.icon_path, icon_file)
            icon = self.load_colored_svg_icon(icon_path, "#FFFFFF")
            btn.setIcon(icon)
            btn.original_icon_path = icon_path
            btn.setIconSize(QtCore.QSize(36, 36))
            btn.setCursor(Qt.PointingHandCursor)
            btn.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            btn.setCheckable(True)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            btn.setStyleSheet("""
                QToolButton {
                    background-color: transparent;
                    border: none;
                    color: white;
                    font-weight: bold;
                }
                QToolButton:hover {
                    background-color: #333;
                    border-radius: 8px;
                }
                QToolButton:checked {
                    background-color: #3a3a3a;
                    border-left: 4px solid #00BCD4;
                    border-radius: 4px;
                    color: #00BCD4;
                }
            """)
            btn.clicked.connect(lambda checked, op=label, b=btn: self.handle_selection(op, b))
            self.menu_layout.addWidget(btn)
            self.menu_buttons[label] = btn

        self.menu_layout.addStretch()
        menu_widget = QWidget()
        menu_widget.setLayout(self.menu_layout)
        menu_widget.setFixedWidth(180)
        main_layout.addWidget(menu_widget)

        # Área dinámica con scroll
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("background-color: #2b2b2b; border: none; margin: 10px;")

        self.content_area = QWidget()
        self.main_area_layout = QVBoxLayout()
        self.content_area.setLayout(self.main_area_layout)

        self.scroll_area.setWidget(self.content_area)
        main_layout.addWidget(self.scroll_area)









    
    #Función para modificar el panel de acuerdo a la selección del usuario
    def handle_selection(self, operation, button):
        if self.selected_button:
            prev_path = self.selected_button.original_icon_path
            self.selected_button.setIcon(self.load_colored_svg_icon(prev_path, "#FFFFFF"))
            self.selected_button.setChecked(False)

        button.setChecked(True)
        self.selected_button = button
        button.setIcon(self.load_colored_svg_icon(button.original_icon_path, "#00BCD4"))
        self.clear_main_area()

        if operation == "Llaves":
            self.show_keygen_ui()
        elif operation == "Notas":
            self.show_notes_ui()
        elif operation == "Cifrar":
            self.show_encrypt_ui()
        elif operation == "Descifrar":
            self.show_decrypt_ui()
        elif operation == "Ocultar":
            self.show_hide_ui()
        elif operation == "Extraer":
            self.show_extract_ui()

    
    #Función para dar color a iconos menú 5 opciones
    def load_colored_svg_icon(self, path, color_hex="#FFFFFF"):
        renderer = QSvgRenderer(path)
        image = QImage(36, 36, QImage.Format_ARGB32)
        image.fill(Qt.transparent)
        painter = QPainter(image)
        renderer.render(painter)
        painter.end()

        painter = QPainter(image)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(image.rect(), QtGui.QColor(color_hex))
        painter.end()

        return QIcon(QPixmap.fromImage(image))



    
    #Función para limpiar el área dinámica inferior antes de mostrar otra operación
    def clear_content(self):
        while self.operation_container.count():
            item = self.operation_container.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
    
    #Función para limpiar el área principal
    def clear_main_area(self):
        while self.main_area_layout.count():
            item = self.main_area_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.setParent(None)
    
   
    #Función guardar llaves pública y privada 
    def show_keygen_ui(self):
        self.clear_main_area()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(30)

        # Título
        title = QLabel("🔑 Administrar llaves")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Descripción
        desc = QLabel("Genera un par de llaves pública y privada para cifrado RSA.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #CCCCCC; font-size: 14px;")
        layout.addWidget(desc)

        # Botón para guardar llaves
        save_btn = QPushButton("Generar un par de llaves")
        save_btn.setCursor(Qt.PointingHandCursor)
        save_btn.setStyleSheet("""
            QPushButton {
                background-color: #00BCD4;
                color: white;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #00a5bb;
            }
        """)
        save_btn.clicked.connect(self.on_create_keys)
        layout.addWidget(save_btn)

        layout.addStretch()

        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)



    
    #Función para generar llaves (Pública y Privada)
    def on_create_keys(self):
        try:
            options = QFileDialog.Options()
            base_path, _ = QFileDialog.getSaveFileName(
                self, "Guardar claves (nombre base)", "", "PEM Files (*.pem);;Todos los archivos (*)", options=options
            )
            if not base_path:
                return  # Cancelado por el usuario

            base_name = base_path.rsplit(".", 1)[0]  # Quitar extensión si la hay

            # Generar clave privada
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Serializar clave privada
            with open(f"{base_name}_private.pem", "wb") as priv_file:
                priv_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            # Serializar clave pública
            with open(f"{base_name}_public.pem", "wb") as pub_file:
                pub_file.write(private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.PKCS1
                ))

            # Confirmación
            QMessageBox.information(
                self, "Éxito",
                f"Claves generadas correctamente:\n{base_name}_private.pem\n{base_name}_public.pem"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudieron generar las llaves:\n{str(e)}")

    #Función para crear notas
    def show_notes_ui(self):
        self.clear_main_area()

        #Scroll principal
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")

        #Container con layout
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(30)
        
        #Título
        title = QLabel("📝 Mis Notas")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        layout.addWidget(title)

        #Descripción
        desc = QLabel("Crea tus notas, cifralas y compartelas con tus contactos de manera segura!")
        desc.setStyleSheet("color: #CCCCCC; font-size: 14px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        #Contenido dinámico - Vista de Notas
        from ui.views.notes_view import NotesView
        notes_view = NotesView()
        layout.addWidget(notes_view)

        #Integrar al scroll
        scroll.setWidget(container)

        #Agregar el container al scroll y el scroll al layout principal        
        self.main_area_layout.addWidget(scroll)
    

    #Función para mostrar el panel de cifrar un archivo
    def show_encrypt_ui(self):
        self.clear_main_area()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(30)

        # Título
        title = QLabel("🔐 Cifrar archivo")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        layout.addWidget(title)

        # Descripción
        desc = QLabel("Selecciona un archivo para cifrar utilizando contraseña o clave pública.")
        desc.setStyleSheet("color: #CCCCCC; font-size: 14px;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Botón principal
        encrypt_btn = QPushButton("Cifrar archivo")
        encrypt_btn.setCursor(Qt.PointingHandCursor)
        encrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #00BCD4;
                color: white;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #00a5bb;
            }
        """)
        encrypt_btn.clicked.connect(self.on_encrypt_file)
        layout.addWidget(encrypt_btn)

        layout.addStretch()
        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)








    #Función para mostrar las opciones de descifrado en el panel
    def show_decrypt_ui(self):
        self.clear_main_area()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(30)

        # Título
        title = QLabel("🔓 Descifrar archivo")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        layout.addWidget(title)

        # Drag & Drop
        self.decrypt_drop = FileDropWidget("📂 Arrastra aquí tu archivo cifrado o haz clic para buscar...")
        layout.addWidget(self.decrypt_drop)

        # Botón descifrar
        self.decrypt_btn = QPushButton("Descifrar archivo")
        self.decrypt_btn.setCursor(Qt.PointingHandCursor)
        self.decrypt_btn.setEnabled(False)  # Desactivado al inicio
        self.decrypt_btn.setStyleSheet("""
            QPushButton {
                background-color: #555;
                color: #aaa;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        self.decrypt_btn.clicked.connect(self.decrypt_file_logic)
        layout.addWidget(self.decrypt_btn)

        # Habilitar el botón cuando se carga un archivo
        def enable_decrypt_button(path):
            self.decrypt_file_path = path
            self.decrypt_btn.setEnabled(True)
            self.decrypt_btn.setStyleSheet("""
                QPushButton {
                    background-color: #00BCD4;
                    color: white;
                    padding: 12px 24px;
                    border-radius: 6px;
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #00a5bb;
                }
            """)

        self.decrypt_drop.fileDropped.connect(enable_decrypt_button)

        layout.addStretch()
        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)

    


    #Función para gestionar el evento cuando el usuario arrastra y suelta un archivo
    def on_file_dropped(self, file_path):
        self.decrypt_file_path = file_path
        self.decrypt_btn.setEnabled(True)
        self.animate_button_activation(self.decrypt_btn)
    

    #Función para animación de botón
    def animate_button_activation(self, button: QPushButton):
        animation = QPropertyAnimation(button, b"styleSheet")
        animation.setDuration(300)
        animation.setEasingCurve(QEasingCurve.InOutQuad)
        animation.setStartValue("""
            QPushButton {
                background-color: #555;
                color: #aaa;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
        """)
        animation.setEndValue("""
            QPushButton {
                background-color: #00BCD4;
                color: white;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #00a5bb;
            }
        """)
        animation.start()
        # Evita que se destruya antes de terminar
        self._current_animation = animation





 

    #Función para seleccionar archivo cifrado
    def browse_encrypted_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "JSON Files (*.json);;Todos los archivos (*)"
        )
        if file_path:
            self.decrypt_file_input.setText(file_path)

    
    #Función que contiene la lógica para descifrar un archivo
    def decrypt_file_logic(self):
        encrypted_file = getattr(self, "decrypt_file_path", "").strip()
        if not os.path.isfile(encrypted_file):
            QtWidgets.QMessageBox.warning(self, "Error", "Archivo no válido o no seleccionado.")
            return

        try:
            with open(encrypted_file, "r", encoding="utf-8") as f:
                payload = json.load(f)

            decrypted_serialized = None
            user_password = None

            # === CIFRADO CON CONTRASEÑA ===
            if all(k in payload for k in ("salt_user", "salt_admin", "encrypted_user_password", "iv_user", "iv_admin", "data")):
                salt_user = bytes.fromhex(payload["salt_user"])
                salt_admin = bytes.fromhex(payload["salt_admin"])
                iv_user = bytes.fromhex(payload["iv_user"])
                iv_admin = bytes.fromhex(payload["iv_admin"])
                encrypted_data = bytes.fromhex(payload["data"])
                encrypted_pwd_bytes = bytes.fromhex(payload["encrypted_user_password"])

                for intento in range(3):
                    dlg = PasswordDialog(confirm=False)
                    if dlg.exec_() != QtWidgets.QDialog.Accepted:
                        return
                    password_input = dlg.get_password().encode("utf-8")

                    try:
                        kdf_user = PBKDF2HMAC(
                            algorithm=hashes.SHA256(), length=32,
                            salt=salt_user, iterations=100000
                        )
                        aes_key_user = kdf_user.derive(password_input)
                        fernet_user = AESGCMWrapper(aes_key_user)
                        decrypted_serialized = fernet_user.decrypt(encrypted_data, iv_user)
                        break
                    except Exception:
                        pass

                    try:
                        kdf_admin = PBKDF2HMAC(
                            algorithm=hashes.SHA256(), length=32,
                            salt=salt_admin, iterations=100000
                        )
                        aes_key_admin = kdf_admin.derive(MASTER_PASSWORD)
                        fernet_admin = AESGCMWrapper(aes_key_admin)
                        user_password = fernet_admin.decrypt(encrypted_pwd_bytes, iv_admin).decode("utf-8")

                        aes_key_user = PBKDF2HMAC(
                            algorithm=hashes.SHA256(), length=32,
                            salt=salt_user, iterations=100000
                        ).derive(user_password.encode("utf-8"))

                        fernet_user = AESGCMWrapper(aes_key_user)
                        decrypted_serialized = fernet_user.decrypt(encrypted_data, iv_user)
                        break
                    except Exception:
                        QtWidgets.QMessageBox.warning(self, "Contraseña incorrecta", f"Intenta nuevamente ({intento+1}/3)")
                else:
                    QtWidgets.QMessageBox.critical(self, "Error", "No se pudo descifrar el archivo tras varios intentos.")
                    return

            # === CIFRADO CON LLAVE PÚBLICA ===
            elif "key_user" in payload and "key_master" in payload and "iv" in payload:
                encrypted_data = bytes.fromhex(payload["data"])
                iv = bytes.fromhex(payload["iv"])

                private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, "Seleccionar tu clave privada (.pem)", "", "PEM Files (*.pem);;Todos los archivos (*)"
                )
                if not private_key_path:
                    return

                with open(private_key_path, "rb") as f:
                    private_key = serialization.load_pem_private_key(f.read(), password=None)

                encrypted_key_user = bytes.fromhex(payload["key_user"])
                encrypted_key_master = bytes.fromhex(payload["key_master"])

                try:
                    aes_key = private_key.decrypt(
                        encrypted_key_user,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                except Exception:
                    aes_key = private_key.decrypt(
                        encrypted_key_master,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )

                fernet = AESGCMWrapper(aes_key)
                decrypted_serialized = fernet.decrypt(encrypted_data, iv)

            else:
                raise Exception("Formato de archivo cifrado no compatible.")

            # === GUARDAR ARCHIVO RESULTADO CON EXTENSIÓN ===
            original_payload = json.loads(decrypted_serialized.decode("utf-8"))
            file_data = base64.b64decode(original_payload["content"])

            filename = original_payload.get("filename", "descifrado")
            ext = original_payload.get("ext", "")
            if ext and not filename.lower().endswith(ext.lower()):
                if not ext.startswith("."):
                    ext = f".{ext}"
                filename += ext

            # Mostrar diálogo para guardar archivo
            suggested_name = filename
            save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Guardar archivo descifrado como", suggested_name, "Todos los archivos (*)"
            )

            if not save_path:
                return

            # Asegurar extensión incluso si el usuario la borra manualmente
            if not os.path.splitext(save_path)[1] and ext:
                if not ext.startswith("."):
                    ext = "." + ext
                save_path += ext

            if not save_path:
                return

            with open(save_path, "wb") as out:
                out.write(file_data)

            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado como:\n{save_path}")

            if user_password:
                QtWidgets.QApplication.clipboard().setText(user_password)
                toast = ToastNotification("Contraseña copiada al portapapeles", parent=self)
                toast.show()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo descifrar el archivo:\n{str(e)}")








   

    
    
    
    #Función diseño de la interfaz para ocultar
    def show_hide_ui(self):
        self.clear_main_area()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(30)

        title = QLabel("📦 Ocultar archivo cifrado")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        layout.addWidget(title)

        desc = QLabel("Inserta un archivo cifrado (.json) dentro de otro archivo contenedor.")
        desc.setStyleSheet("color: white; font-weight: 500;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # === Drag & Drop 1 ===
        self.container_drop = FileDropWidget("🗂️ Arrastra el archivo contenedor o haz clic para buscar...")
        layout.addWidget(self.container_drop)

        # === Drag & Drop 2 ===
        self.hidden_drop = FileDropWidget("🔐 Arrastra el archivo cifrado (.json) o haz clic para buscar...")
        layout.addWidget(self.hidden_drop)

        # === Botón
        self.hide_btn = QPushButton("Ocultar archivo dentro del contenedor")
        self.hide_btn.setEnabled(False)
        self.hide_btn.setCursor(Qt.PointingHandCursor)
        self.hide_btn.clicked.connect(self.hide_encrypted_file_logic)
        self.hide_btn.setStyleSheet("""
            QPushButton {
                background-color: #555;
                color: #ccc;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover:enabled {
                background-color: #00a5bb;
                color: white;
            }
            QPushButton:enabled {
                background-color: #00BCD4;
                color: white;
            }
        """)
        layout.addWidget(self.hide_btn)

        # === Función para validar estado ===
        def validate_inputs():
            cont = getattr(self.container_drop, "file_path", None)
            hide = getattr(self.hidden_drop, "file_path", None)
            self.hide_btn.setEnabled(bool(cont and hide))

        # === Conectar Drop + Actualizar valor y validar ===
        self.container_drop.fileDropped.connect(
            lambda path: (self.container_drop.set_file_path(path), validate_inputs())
        )
        self.hidden_drop.fileDropped.connect(
            lambda path: (self.hidden_drop.set_file_path(path), validate_inputs())
        )

        layout.addStretch()
        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)


    

    #Función que evalúa si el 1er campo contiene un archivo (show_hide_ui)
    def on_container_file_dropped(self, path):
        self.container_file_path = path
        self.evaluate_hide_button_ready()

    #Función que evalúa si el 2do campo contiene un archivo (show_hide_ui)
    def on_hidden_file_dropped(self, path):
        self.hidden_file_path = path
        self.evaluate_hide_button_ready()

    #Función que activa el botón para ocultar archivo (show_hide_ui)
    def evaluate_hide_button_ready(self):
        if hasattr(self, "container_file_path") and hasattr(self, "hidden_file_path"):
            self.hide_btn.setEnabled(True)
            self.animate_button_activation(self.hide_btn)



    
    #Método para que el botón para seleccionar archivo contenedor funcione
    def browse_container_file(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor", "", "Todos los archivos (*)"
        )
        if path:
            self.container_input.setText(path)

    #Método para que el botón para seleccionar archivo cifrado funcione
    def browse_encrypted_file_to_hide(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "JSON Files (*.json);;Todos los archivos (*)"
        )
        if path:
            self.encrypted_input.setText(path)
    
    
    
    #Función para ocultar archivo cifrado (esteganografía)
    def hide_encrypted_file_logic(self):
        # Obtener rutas desde los widgets de arrastrar/soltar
        contenedor_path = getattr(self.container_drop, "file_path", "").strip()
        cifrado_path = getattr(self.hidden_drop, "file_path", "").strip()

        # Validación
        if not contenedor_path or not cifrado_path:
            QtWidgets.QMessageBox.warning(self, "Campos incompletos", "Debes seleccionar ambos archivos.")
            return

        if not os.path.isfile(contenedor_path) or not os.path.isfile(cifrado_path):
            QtWidgets.QMessageBox.warning(self, "Error", "Uno o ambos archivos no son válidos.")
            return

        if not cifrado_path.endswith(".json"):
            QtWidgets.QMessageBox.warning(self, "Archivo incorrecto", "El archivo cifrado debe ser un archivo .json.")
            return

        try:
            # Leer ambos archivos
            with open(contenedor_path, "rb") as f1:
                contenedor = f1.read()
            with open(cifrado_path, "rb") as f2:
                cifrado = f2.read()

            # Agregar delimitador para incrustación
            firmado = contenedor + b"<<--BETTY_START-->>" + cifrado

            # Sugerir extensión original del contenedor
            ext = os.path.splitext(contenedor_path)[1] or ".dat"
            
            # Recuperar nombre original del archivo cifrado (si es .json válido)
            try:
                with open(cifrado_path, "r") as f:
                    contenido_json = json.load(f)
                nombre_original = os.path.splitext(os.path.basename(contenido_json.get("filename", "")))[0]
                nombre_sugerido = f"{nombre_original}_oculto{ext}"
            except:
                nombre_sugerido = f"oculto{ext}"


            # Selección de destino
            ruta_salida, _ = QtWidgets.QFileDialog.getSaveFileName(
                self,
                "Guardar archivo combinado",
                nombre_sugerido,
                f"Archivos (*{ext});;Todos los archivos (*)"
            )
            if not ruta_salida:
                return

            # Guardar archivo combinado
            with open(ruta_salida, "wb") as out:
                out.write(firmado)

            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo oculto guardado como:\n{ruta_salida}")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo ocultar el archivo:\n{str(e)}")



    

    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    #Función que muestra los campos en la interfaz para extracción de archivos
    def show_extract_ui(self):
        self.clear_main_area()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(50, 40, 50, 40)
        layout.setSpacing(30)

        # Título
        title = QLabel("📤 Extraer archivo oculto")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        layout.addWidget(title)

        # Descripción
        desc = QLabel("Selecciona un archivo contenedor que tenga un archivo cifrado incrustado.")
        desc.setStyleSheet("color: white;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Área Drag & Drop
        self.extract_drop = FileDropWidget("🗂️ Arrastra el archivo contenedor aquí o haz clic para buscar...")
        layout.addWidget(self.extract_drop)

        # Activar botón si se carga archivo válido
        def on_extract_file_dropped(path):
            if os.path.isfile(path):
                self.extract_drop.set_file_path(path)
                self.extract_btn.setEnabled(True)
            else:
                self.extract_btn.setEnabled(False)

        self.extract_drop.fileDropped.connect(on_extract_file_dropped)

        # Botón de extracción
        self.extract_btn = QPushButton("Extraer archivo oculto")
        self.extract_btn.setEnabled(False)
        self.extract_btn.setCursor(Qt.PointingHandCursor)
        self.extract_btn.clicked.connect(self.extract_hidden_file_logic)
        self.extract_btn.setStyleSheet("""
            QPushButton {
                background-color: #555;
                color: #ccc;
                padding: 12px 24px;
                border-radius: 6px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover:enabled {
                background-color: #00a5bb;
                color: white;
            }
            QPushButton:enabled {
                background-color: #00BCD4;
                color: white;
            }
        """)
        layout.addWidget(self.extract_btn)

        layout.addStretch()
        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)

    

    #Método auxiliar para la función de extraer archivos (Drag and Drop)
    def on_extract_file_dropped(self, path):
        self.extract_file_path = path
        self.extract_btn.setEnabled(True)
        self.animate_button_activation(self.extract_btn)



    
    #Función contiene la lógica para extraer archivo
    def extract_hidden_file_logic(self):
        try:
            # Obtener la ruta del archivo contenedor desde el widget de arrastrar/soltar
            contenedor_path = getattr(self.extract_drop, "file_path", "").strip()

            if not contenedor_path or not os.path.isfile(contenedor_path):
                QtWidgets.QMessageBox.warning(self, "Error", "Debes seleccionar un archivo contenedor válido.")
                return

            # Leer el archivo completo
            with open(contenedor_path, "rb") as f:
                contenido = f.read()

            # Buscar el delimitador que separa el contenido original y el archivo oculto
            delimiter = b"<<--BETTY_START-->>"
            idx = contenido.find(delimiter)

            if idx == -1:
                raise Exception("No se encontró ningún archivo oculto en este contenedor.")

            # Extraer la parte cifrada
            cifrado = contenido[idx + len(delimiter):]

            # Sugerencia de nombre de salida con extensión .json
            nombre_base = os.path.splitext(os.path.basename(contenedor_path))[0]
            
            # Extraer nombre original desde el JSON si es posible
            try:
                cifrado_json = json.loads(cifrado.decode("utf-8"))
                nombre_original = cifrado_json.get("filename", nombre_base)
                nombre_sugerido = f"{nombre_original}_extraido.json"
            except:
                nombre_sugerido = f"{nombre_base}_extraido.json"

            #Sugerir carpeta para guardar archivo extraido 
            carpeta_inicial = os.path.dirname(contenedor_path)

            output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self,
                "Guardar archivo extraído",
                os.path.join(carpeta_inicial, nombre_sugerido),
                "Archivos JSON (*.json);;Todos los archivos (*)"
            )
            if not output_path:
                return

            # Guardar el archivo cifrado extraído
            with open(output_path, "wb") as out:
                out.write(cifrado)

            reply = QtWidgets.QMessageBox.question(
                self, "¿Descifrar ahora?",
                f"Archivo extraído en:\n{output_path}\n\n¿Deseas descifrarlo ahora?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )

            if reply == QtWidgets.QMessageBox.Yes:
                self.descifrar_archivo_extraido(output_path)

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo extraer el archivo:\n{str(e)}")







    #++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    #Función botón para retornar al menú de opciones principal
    def create_back_button(self):
        btn = QPushButton("  Volver al menú")
        btn.setIcon(QIcon(os.path.join(self.icon_path, "back.png")))
        btn.setIconSize(QtCore.QSize(24, 24))
        btn.setCursor(Qt.PointingHandCursor)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #2c2c2c;
                color: white;
                padding: 10px;
                border-radius: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #444;
            }
        """)
        btn.clicked.connect(self.show_menu)
        return btn
    





    #+++++FUNCIONES PRINCIPALES++++++placeholder+++++

    #Función para cifrar un archivo
    def on_encrypt_file(self):
        # Seleccionar archivo a cifrar
        input_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo a cifrar", "", "Todos los archivos (*)"
        )
        if not input_file:
            return

        # Mostrar nuevo diálogo visual
        dlg = EncryptionMethodDialog()
        if dlg.exec_() != QtWidgets.QDialog.Accepted:
            return

        metodo = dlg.selected_method()
        if metodo == "Seleccione una opción...":
            QtWidgets.QMessageBox.warning(
                self, "Método requerido",
                "Por favor selecciona un método de cifrado válido."
            )
            return

        # Seleccionar ubicación de guardado
        original_name = os.path.splitext(os.path.basename(input_file))[0]
        output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo cifrado", f"{original_name}_Cif.json",
            "JSON Files (*.json);;Todos los archivos (*)"
)


        if not output_path:
            return

        try:
            if metodo == "Contraseña":
                # Cifrado con contraseña
                dlg_pwd = PasswordDialog()
                if dlg_pwd.exec_() == QtWidgets.QDialog.Accepted:
                    password = dlg_pwd.get_password()
                    cifrar_archivo_con_password(input_file, password, output_path)
                    QtWidgets.QMessageBox.information(
                        self, "Éxito",
                        f"Archivo cifrado con contraseña guardado en:\n{output_path}"
                    )
            else:
                # Cifrado con clave pública
                public_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                    self, "Seleccionar clave pública del destinatario", "",
                    "PEM Files (*.pem);;Todos los archivos (*)"
                )
                if not public_key_path:
                    return

                cifrar_archivo_con_rsa(input_file, public_key_path, output_path)
                QtWidgets.QMessageBox.information(
                    self, "Éxito",
                    f"Archivo cifrado con llave de seguridad guardado en:\n{output_path}"
                )

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo cifrar el archivo:\n{str(e)}")





        



    #Función para ocultar archivo cifrado en contenedor
    def on_hide_file(self):
        #Seleccionar archivo cifrado (.json)
        cifrado_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "Archivo Cifrado (*.json);;All Files (*)")
        
        if not cifrado_path:
            return
        
        #Seleccionar archivo contenedor (imagen, audio, documento, etc.)
        contenedor_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor", "", "Todos los archivos (*)")
        
        if not contenedor_path:
            return
        
        #Obtener extensión original del archivo contenedor
        cont_ext = os.path.splitext(contenedor_path)[1]

        #Seleccionar dónde guardar el archivo oculto
        destino_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo oculto", f"oculto{cont_ext}", f"Archivo Contenedor (*{cont_ext})")
        
        if not destino_path:
            return
        
        try:
            with open(contenedor_path, "rb") as cont_file:
                cont_data = cont_file.read()
            with open(cifrado_path, "rb") as cif_file:
                 cif_data = cif_file.read()
            
            #Marcar el inicio del contenido oculto con una firma única
            firma = b"<<--BETTY_START-->>"
            oculto = cont_data + firma + cif_data

            with open(destino_path, "wb") as salida:
                salida.write(oculto)
            
            #Imprimir mensaje de éxito al guardar archivo oculto
            QtWidgets.QMessageBox.information(
                self, "Éxito", f"Archivo oculto guardado como:\n{destino_path}"
            )

        except Exception as e:
            #imprimir mensaje de error al guardar archivo oculto
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo ocultar el archivo:\n{e}")


    
    #Función para extraer archivo y descifrar
    def on_extract_hidden_file(self):
        #Seleccionar archivo contenedor
        contenedor_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor", "", "All Files (*)"
        )

        if not contenedor_path:
            return
        
        #Leer contenido del contenedor y buscar delimitador
        try:
            with open(contenedor_path, "rb") as f:
                contenido = f.read()
            
            delimiter = b"<<--BETTY_START-->>"
            idx = contenido.find(delimiter)
            if idx == -1:
                raise Exception("El contenedor está vacío, no se encontró ningún archivo.")
            
            cifrado_data = contenido[idx + len(delimiter):]

            #Forzar extensión del archivo extraido (.json)
            ext = ".json"

            #Proponer un nombre de archivo con extensión .json
            output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self,
                "Guardar archivo extraido",
                "extraido.json",
                "Archivo Cifrado (*.json);; All Files (*)"
            )
            
            if not output_path:
                return
            
            with open(output_path, "wb") as out:
                out.write(cifrado_data)
            
            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo extraído y guardado en:\n{output_path}")
            
            '''
            #Preguntar si desea descifrarlo ahora
            reply = QtWidgets.QMessageBox.question(
                self, "¿Descifrar ahora?",
                "¿Desea descifrar el archivo extraído?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            
            if reply == QtWidgets.QMessageBox.Yes:
                self.descifrar_archivo_extraido(output_path)
            '''

        #Imprimir mensaje de error al extraer archivo        
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo extraer el archivo:\n{e}")


         
#+++++FUNCIONES AUXILIARES+++++INICIO+++++

#Función para cifrar un archivo con RSA
def cifrar_archivo_con_rsa(input_path, public_key_path, output_path):
    import json, base64, os
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from ui.panels.encryption_panel import PUBLIC_KEY_PEM, get_client_uuid

    with open(input_path, "rb") as f:
        file_data = f.read()

    ext = os.path.splitext(input_path)[1].lower() or ".bin"
    payload = {
        "filename": os.path.basename(input_path),
        "ext": ext,
        "content": base64.b64encode(file_data).decode("utf-8")
    }
    serialized = json.dumps(payload).encode("utf-8")

    aes_key = os.urandom(32)
    gcm = AESGCMWrapper(aes_key)
    iv, encrypted_data = gcm.encrypt(serialized)

    with open(public_key_path, "rb") as f:
        pub_user = serialization.load_pem_public_key(f.read())
    pub_master = serialization.load_pem_public_key(PUBLIC_KEY_PEM)

    encrypted_key_user = pub_user.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_key_master = pub_master.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    result = {
        "type": "rsa",
        "filename": os.path.basename(input_path),
        "ext": ext,
        "created_by": get_client_uuid(),
        "key_user": encrypted_key_user.hex(),
        "key_master": encrypted_key_master.hex(),
        "iv": iv.hex(),
        "data": encrypted_data.hex()
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)







#Función para descifrar un archivo con RSA
def descifrar_archivo_con_rsa(input_path, private_key_path):
    import json, base64
    import os
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    

    with open(input_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    encrypted_data = bytes.fromhex(payload["data"])
    iv = bytes.fromhex(payload["iv"])
    encrypted_key_user = bytes.fromhex(payload["key_user"])
    encrypted_key_master = bytes.fromhex(payload["key_master"])

    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    try:
        aes_key = priv_key.decrypt(
            encrypted_key_user,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
    except Exception:
        aes_key = priv_key.decrypt(
            encrypted_key_master,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    gcm = AESGCMWrapper(aes_key)
    decrypted_serialized = gcm.decrypt(encrypted_data, iv)

    original = json.loads(decrypted_serialized.decode("utf-8"))
    file_data = base64.b64decode(original["content"])
    return original["filename"], file_data








#Función para ocultar archivo cifrado en un contenedor
def ocultar_archivo_en_contenedor(contenedor_path, archivo_oculto_path, salida_path):
    with open(contenedor_path, "rb") as contenedor:
        contenedor_data = contenedor.read()

    with open(archivo_oculto_path, "rb") as archivo_oculto:
        datos_ocultos = archivo_oculto.read()

    #Añade una firma
    firma = b"<<--BETTY_START-->>"

    with open(salida_path, "wb") as salida:
        salida.write(contenedor_data)
        salida.write(firma)
        salida.write(datos_ocultos) 

#Función para descifrar archivo extraido
def descifrar_archivo_extraido(self, encrypted_path):
    if not os.path.isfile(encrypted_path):
        QtWidgets.QMessageBox.warning(self, "Error", "Archivo no válido.")
        return

    try:
        with open(encrypted_path, "r", encoding="utf-8") as f:
            payload = json.load(f)

        tipo = payload.get("type")
        decrypted_serialized = None

        if tipo == "rsa":
            private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Seleccionar clave privada (.pem)", "", "PEM Files (*.pem)"
            )
            if not private_key_path:
                return

            encrypted_data = bytes.fromhex(payload["data"])
            iv = bytes.fromhex(payload["iv"])
            encrypted_key_user = bytes.fromhex(payload["key_user"])
            encrypted_key_master = bytes.fromhex(payload["key_master"])

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            try:
                aes_key = private_key.decrypt(
                    encrypted_key_user,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            except Exception:
                aes_key = private_key.decrypt(
                    encrypted_key_master,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

            fernet = AESGCMWrapper(aes_key)
            decrypted_serialized = fernet.decrypt(encrypted_data, iv)

        elif tipo == "password":
            for intento in range(3):
                dlg = PasswordDialog(confirm=False)
                if dlg.exec_() != QtWidgets.QDialog.Accepted:
                    return
                password = dlg.get_password().encode("utf-8")

                salt_user = bytes.fromhex(payload["salt_user"])
                salt_admin = bytes.fromhex(payload["salt_admin"])
                iv_user = bytes.fromhex(payload["iv_user"])
                iv_admin = bytes.fromhex(payload["iv_admin"])
                encrypted_data = bytes.fromhex(payload["data"])
                encrypted_pwd = bytes.fromhex(payload["encrypted_user_password"])

                try:
                    kdf_user = PBKDF2HMAC(hashes.SHA256(), 32, salt_user, 100000)
                    aes_key_user = kdf_user.derive(password)
                    gcm_user = AESGCMWrapper(aes_key_user)
                    decrypted_serialized = gcm_user.decrypt(encrypted_data, iv_user)
                    break
                except Exception:
                    pass

                try:
                    kdf_admin = PBKDF2HMAC(hashes.SHA256(), 32, salt_admin, 100000)
                    aes_key_admin = kdf_admin.derive(MASTER_PASSWORD)
                    gcm_admin = AESGCMWrapper(aes_key_admin)
                    recovered_pwd = gcm_admin.decrypt(encrypted_pwd, iv_admin).decode("utf-8")

                    aes_key_user = PBKDF2HMAC(hashes.SHA256(), 32, salt_user, 100000).derive(recovered_pwd.encode("utf-8"))
                    decrypted_serialized = AESGCMWrapper(aes_key_user).decrypt(encrypted_data, iv_user)
                    break
                except Exception:
                    QtWidgets.QMessageBox.warning(self, "Contraseña incorrecta", f"Intenta nuevamente ({intento+1}/3)")
            else:
                QtWidgets.QMessageBox.critical(self, "Error", "No se pudo descifrar el archivo.")
                return

        else:
            raise Exception("Formato no compatible.")

        # === GUARDAR CON EXTENSIÓN ===
        original_payload = json.loads(decrypted_serialized.decode("utf-8"))
        file_data = base64.b64decode(original_payload["content"])

        filename = original_payload.get("filename", "descifrado")
        ext = original_payload.get("ext", "")
        if ext and not filename.lower().endswith(ext.lower()):
            if not ext.startswith("."):
                ext = f".{ext}"
            filename += ext


        # Mostrar diálogo para guardar archivo
        suggested_name = filename
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado como", suggested_name, "Todos los archivos (*)"
        )

        if not save_path:
            return

        # Asegurar extensión incluso si el usuario la borra manualmente
        if not os.path.splitext(save_path)[1] and ext:
            if not ext.startswith("."):
                ext = "." + ext
            save_path += ext

        if not save_path:
            return

        with open(save_path, "wb") as out:
            out.write(file_data)

        QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado en:\n{save_path}")

    except Exception as e:
        QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo descifrar el archivo:\n{str(e)}")





#Generar contraseña segura para cifrado
class PasswordDialog(QtWidgets.QDialog):
    def __init__(self, confirm=True):
        super().__init__()
        self.setWindowTitle("Contraseña")
        self.setFixedSize(350, 200 if confirm else 110)
        self.confirm = confirm

        layout = QtWidgets.QVBoxLayout(self)

        self.label = QtWidgets.QLabel("Ingresa una contraseña segura:" if confirm else "Ingresa la contraseña:")
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setPlaceholderText("Contraseña")
        layout.addWidget(self.label)
        layout.addWidget(self.password_input)

        if confirm:
            self.confirm_input = QtWidgets.QLineEdit()
            self.confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)
            self.confirm_input.setPlaceholderText("Confirmar contraseña")
            layout.addWidget(self.confirm_input)

            self.strength_bar = QtWidgets.QProgressBar()
            self.strength_bar.setRange(0, 100)
            self.strength_bar.setTextVisible(False)
            self.strength_bar.hide()

            self.strength_label = QtWidgets.QLabel("")
            self.strength_label.hide()

            layout.addWidget(self.strength_bar)
            layout.addWidget(self.strength_label)

            self.password_input.textChanged.connect(self.update_strength)

        self.button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.validate)
        self.button_box.rejected.connect(self.reject)
        layout.addWidget(self.button_box)

    def update_strength(self, text):
        if not text:
            self.strength_bar.hide()
            self.strength_label.hide()
            return
        else:
            self.strength_bar.show()
            self.strength_label.show()

        has_lower = any(c.islower() for c in text)
        has_upper = any(c.isupper() for c in text)
        has_digit = any(c.isdigit() for c in text)
        has_symbol = any(c in "!@#$%^&*()_+-=,.;:<>?" for c in text)
        length_ok = len(text) >= 8

        strength = sum([has_lower, has_upper, has_digit, has_symbol]) * 25
        strength = min(strength, 100)  #Limita al 100%

        if not length_ok or strength < 50:
            label = "Débil"
            color = "red"
        elif strength < 75:
            label = "Media"
            color = "orange"
        else:
            label = "Fuerte"
            color = "green"

        self.strength_bar.setValue(strength)
        self.strength_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)
        self.strength_label.setText(f"Fortaleza: {label}")
        self.strength_label.setStyleSheet(f"color: {color}; font-weight: bold;")

    def validate(self):
        pwd = self.password_input.text()

        if self.confirm:
            confirm = self.confirm_input.text()
            if pwd != confirm:
                QtWidgets.QMessageBox.warning(self, "Error", "Las contraseñas no coinciden.")
                return

            if len(pwd) < 8:
                QtWidgets.QMessageBox.warning(self, "Error", "Debe tener al menos 8 caracteres.")
                return

            conditions = [
                any(c.islower() for c in pwd),
                any(c.isupper() for c in pwd),
                any(c.isdigit() for c in pwd),
                any(c in "!@#$%^&*()-_=+[{]};:,.<>?" for c in pwd)
            ]
            strength = sum(conditions) * 25

            if strength < 75:
                QtWidgets.QMessageBox.warning(self, "Error", "La contraseña debe ser más segura (nivel medio o fuerte).")
                return

        self.accept()

    def get_password(self):
        return self.password_input.text()


#clase y Función para solicitar contraseña al descifrar un archivo
class PasswordPromptDialog(QtWidgets.QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Ingresar contraseña")
        self.setFixedSize(300, 120)

        layout = QtWidgets.QVBoxLayout()

        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.setPlaceholderText("Contraseña")
        layout.addWidget(QtWidgets.QLabel("Ingrese la contraseña de cifrado:"))
        layout.addWidget(self.password_input)

        buttons = QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel
        self.button_box = QtWidgets.QDialogButtonBox(buttons)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        layout.addWidget(self.button_box)        
        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()


class ToastNotification(QWidget):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)

        #Layout interno con ícono y texto
        layout = QHBoxLayout(self)
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(10)

        icon_label = QLabel("🔐")
        icon_label.setFont(QFont("Arial", 16))
        layout.addWidget(icon_label)

        text_label = QLabel(text)
        text_label.setStyleSheet("color: white; font-size: 12pt;")
        layout.addWidget(text_label)

        #Estilo del fondo del toast
        self.setStyleSheet("""
            QWidget {
                background-color: #323232;
                border-radius: 8px;
            }
        """)

        self.adjustSize()

        #Centrar en pantalla
        screen = QtWidgets.QApplication.desktop().screenGeometry()
        self.move(screen.center() - self.rect().center())

        QTimer.singleShot(3000, self.close)  #Se oculta en 3 segundos


#Función para cifrar contraseña con llave maestra
def cifrar_contrasena_con_llave_maestra(aes_key: bytes) -> str:
    pub_master = serialization.load_pem_public_key(PUBLIC_KEY_PEM, backend=default_backend())
    encrypted_key = pub_master.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key.hex()



#Función para cifrar con contraseña
def cifrar_archivo_con_password(input_path, password, output_path):
    import json, base64, os
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from ui.panels.encryption_panel import MASTER_PASSWORD, get_client_uuid

    with open(input_path, "rb") as f:
        file_data = f.read()

    ext = os.path.splitext(input_path)[1].lower() or ".bin"
    if not ext.startswith("."):
        ext = f".{ext}"

    payload = {
        "filename": os.path.basename(input_path),
        "ext": ext,
        "content": base64.b64encode(file_data).decode("utf-8")
    }
    serialized = json.dumps(payload).encode("utf-8")

    # Asegurar que password sea bytes
    if isinstance(password, bytes):
        password_bytes = password
    elif isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        raise ValueError("Contraseña inválida: debe ser str o bytes.")

    # Derivar clave del usuario
    salt_user = os.urandom(16)
    kdf_user = PBKDF2HMAC(hashes.SHA256(), 32, salt_user, 100000)
    aes_key_user = kdf_user.derive(password_bytes)
    gcm_user = AESGCMWrapper(aes_key_user)
    iv_user, encrypted_data = gcm_user.encrypt(serialized)

    # Derivar clave del admin
    salt_admin = os.urandom(16)
    kdf_admin = PBKDF2HMAC(hashes.SHA256(), 32, salt_admin, 100000)
    aes_key_admin = kdf_admin.derive(MASTER_PASSWORD)  # ya es bytes
    gcm_admin = AESGCMWrapper(aes_key_admin)
    iv_admin, encrypted_pwd = gcm_admin.encrypt(password_bytes)

    result = {
        "type": "password",
        "filename": os.path.basename(input_path),
        "ext": ext,
        "created_by": get_client_uuid(),
        "salt_user": salt_user.hex(),
        "iv_user": iv_user.hex(),
        "salt_admin": salt_admin.hex(),
        "iv_admin": iv_admin.hex(),
        "encrypted_user_password": encrypted_pwd.hex(),
        "data": encrypted_data.hex()
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)











#Función para descifrar con password
def descifrar_archivo_con_password(input_path, password):
    import json, base64
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes    
    from ui.panels.encryption_panel import MASTER_PASSWORD

    with open(input_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    encrypted_data = bytes.fromhex(payload["data"])
    salt_user = bytes.fromhex(payload["salt_user"])
    iv_user = bytes.fromhex(payload["iv_user"])
    salt_admin = bytes.fromhex(payload["salt_admin"])
    iv_admin = bytes.fromhex(payload["iv_admin"])
    encrypted_pwd = bytes.fromhex(payload["encrypted_user_password"])

    try:
        kdf_user = PBKDF2HMAC(hashes.SHA256(), 32, salt_user, 100000)
        aes_key_user = kdf_user.derive(password.encode("utf-8"))
        gcm_user = AESGCMWrapper(aes_key_user)
        decrypted_serialized = gcm_user.decrypt(encrypted_data, iv_user)
    except Exception:
        kdf_admin = PBKDF2HMAC(hashes.SHA256(), 32, salt_admin, 100000)
        aes_key_admin = kdf_admin.derive(MASTER_PASSWORD.encode("utf-8"))
        gcm_admin = AESGCMWrapper(aes_key_admin)
        user_password = gcm_admin.decrypt(encrypted_pwd, iv_admin).decode("utf-8")

        aes_key_user = PBKDF2HMAC(hashes.SHA256(), 32, salt_user, 100000).derive(user_password.encode("utf-8"))
        decrypted_serialized = AESGCMWrapper(aes_key_user).decrypt(encrypted_data, iv_user)

    original = json.loads(decrypted_serialized.decode("utf-8"))
    file_data = base64.b64decode(original["content"])
    return original["filename"], file_data


#+++++FUNCIONES AUXILIARES+++++FIN+++++
