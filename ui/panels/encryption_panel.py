from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QGroupBox, QGridLayout, QToolButton, QSizePolicy
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, json, os
from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import os, json
from cryptography.fernet import Fernet
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
from PyQt5.QtCore import QTimer, Qt, QSize
from PyQt5.QtWidgets import QLabel
from PyQt5.QtGui import QIcon, QPixmap, QPainter, QImage, QColor
from PyQt5.QtWidgets import QComboBox
import json
import base64
from PyQt5.QtWidgets import QInputDialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtGui import QPainter, QImage


#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Clave pública maestra
MASTER_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwF4EDZIm66+kJZlTTiV
TtxAxr60j2CmxLfLBfdvuJdKadmV4i6yatfRSeS+ZGCAFBKwb+jHNNWv2VyWDyGO
3vWqBA4OI69jCFF1R9cOJY4bzDmxB1pB9KgfVX3HtvyMe3Zu8q7+6s6IcthHmaoK
xcXLKTjcsQlVb7hcWMVYaaSwyiPxtRnF/Tk42ys0eps66rM9EKi+K6/mnSzjhquS
XlGY+O2HxGq+H3K8kP8R6iLU09mm5Q11PBoir12wiHQ8m8NiTKzCLAOAt2CCBpyu
UIu1Bie1A04MPaKuvKXpnML5Ib9LGiXcjI6kvjOXhrj1dT8ES8JALGJWnohYZjkJ
0wIDAQAB
-----END PUBLIC KEY-----"""

MASTER_PASSWORD = b'SeguraAdmin123!'
#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

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
            ("Crear llaves", "keys.svg"),
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

        if operation == "Crear llaves":
            self.show_keygen_ui()
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
        title = QLabel("🔑 Crear llaves")
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        title.setAlignment(Qt.AlignLeft)
        layout.addWidget(title)

        # Descripción
        desc = QLabel("Genera un par de llaves pública y privada para cifrado RSA.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #CCCCCC; font-size: 14px;")
        layout.addWidget(desc)

        # Botón para guardar llaves
        save_btn = QPushButton("Guardar llaves en archivo")
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
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            # Confirmación
            QMessageBox.information(
                self, "Éxito",
                f"Claves generadas correctamente:\n{base_name}_private.pem\n{base_name}_public.pem"
            )

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudieron generar las llaves:\n{str(e)}")


    

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
        title.setStyleSheet("font-size: 22px; font-weight: bold; color: white;")
        layout.addWidget(title)

        # Campo para archivo cifrado
        file_row = QHBoxLayout()
        self.decrypt_file_input = QLineEdit()
        self.decrypt_file_input.setPlaceholderText("Selecciona el archivo .json")
        self.decrypt_file_input.setStyleSheet("padding: 8px;")
        file_row.addWidget(self.decrypt_file_input)

        browse_btn = QPushButton("📂 Buscar")
        browse_btn.setCursor(Qt.PointingHandCursor)
        browse_btn.clicked.connect(self.browse_encrypted_file)
        file_row.addWidget(browse_btn)
        layout.addLayout(file_row)

        # Botón descifrar
        decrypt_btn = QPushButton("Descifrar archivo")
        decrypt_btn.setCursor(Qt.PointingHandCursor)
        decrypt_btn.setStyleSheet("""
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
        decrypt_btn.clicked.connect(self.decrypt_file_logic)
        layout.addWidget(decrypt_btn)

        layout.addStretch()
        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)




 

    #Función para seleccionar archivo cifrado
    def browse_encrypted_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "JSON Files (*.json);;Todos los archivos (*)"
        )
        if file_path:
            self.decrypt_file_input.setText(file_path)

    #Función que contiene la lógica para descifrar un archivo
    def decrypt_file_logic(self):
        encrypted_file = self.decrypt_file_input.text().strip()
        if not os.path.isfile(encrypted_file):
            QtWidgets.QMessageBox.warning(self, "Error", "Archivo no válido o no seleccionado.")
            return

        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado como", "descifrado", "Todos los archivos (*)"
        )
        if not save_path:
            return

        try:
            with open(encrypted_file, "r") as f:
                payload = json.load(f)

            encrypted_data = bytes.fromhex(payload["data"])
            ext = payload.get("ext", "")
            decrypted_serialized = None
            user_password = None  #se usa si fue descifrado como admin

            #=== CIFRADO CON CONTRASEÑA ===
            if "salt_user" in payload and "salt_admin" in payload and "encrypted_user_password" in payload:
                salt_user = base64.b64decode(payload["salt_user"])
                salt_admin = base64.b64decode(payload["salt_admin"])
                encrypted_pwd_bytes = bytes.fromhex(payload["encrypted_user_password"])

                intentos = 0
                max_intentos = 3
                while intentos < max_intentos:
                    dlg = PasswordDialog(confirm=False)
                    if dlg.exec_() != QtWidgets.QDialog.Accepted:
                        return
                    password_input = dlg.get_password()

                    try:
                        #Intentar con contraseña del usuario
                        kdf_user = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_user, iterations=100000)
                        aes_key_user = base64.urlsafe_b64encode(kdf_user.derive(password_input.encode()))
                        fernet_user = Fernet(aes_key_user)
                        decrypted_serialized = fernet_user.decrypt(encrypted_data)
                        break  #Éxito usuario

                    except Exception:
                        try:
                            #Intentar como administrador
                            kdf_admin = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_admin, iterations=100000)
                            aes_key_admin = base64.urlsafe_b64encode(kdf_admin.derive(password_input.encode()))
                            fernet_admin = Fernet(aes_key_admin)

                            #Recuperar contraseña real del usuario
                            user_password = fernet_admin.decrypt(encrypted_pwd_bytes).decode()

                            #Usar contraseña del usuario para descifrar
                            kdf_user = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_user, iterations=100000)
                            aes_key_user = base64.urlsafe_b64encode(kdf_user.derive(user_password.encode()))
                            fernet_user = Fernet(aes_key_user)
                            decrypted_serialized = fernet_user.decrypt(encrypted_data)
                            break  #Éxito como admin

                        except Exception:
                            intentos += 1
                            if intentos < max_intentos:
                                QtWidgets.QMessageBox.warning(self, "Contraseña incorrecta", f"Intenta nuevamente ({intentos}/{max_intentos})")
                            else:
                                QtWidgets.QMessageBox.critical(self, "Error", "No se pudo descifrar el archivo tras varios intentos.")
                                return

            #=== CIFRADO CON CLAVE PÚBLICA ===
            elif "key_user" in payload and "key_master" in payload:
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

                fernet = Fernet(aes_key)
                decrypted_serialized = fernet.decrypt(encrypted_data)

            else:
                raise Exception("Formato de archivo cifrado no compatible.")

            #=== GUARDAR ARCHIVO DESCIFRADO ===
            original_payload = json.loads(decrypted_serialized.decode("utf-8"))
            ext = original_payload.get("ext", ext)
            file_data = base64.b64decode(original_payload["content"])

            if ext and not save_path.endswith(ext):
                save_path += ext

            with open(save_path, "wb") as out:
                out.write(file_data)

            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado como:\n{save_path}")

            #=== MOSTRAR CONTRASEÑA ORIGINAL (si se descifró como admin) ===
            if user_password:
                QtWidgets.QApplication.clipboard().setText(user_password)
                toast = ToastNotification("Contraseña copiada al portapapeles", parent=self)
                toast.show()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo descifrar el archivo:\n{str(e)}")   

    
    
    
    #Función que muestra los campos en la interfaz para ocultar
    def show_hide_ui(self):
        self.clear_main_area()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: #2b2b2b; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("🫙 Ocultar archivo cifrado")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        layout.addWidget(title)

        desc = QLabel("Inserta un archivo cifrado (.json) dentro de otro archivo contenedor.")
        desc.setStyleSheet("color: white;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        label1 = QLabel("Selecciona el archivo contenedor:")
        label1.setStyleSheet("color: white;")
        layout.addWidget(label1)

        self.container_input = QLineEdit()
        browse_container = QPushButton("📂 Buscar")
        browse_container.clicked.connect(lambda: self.browse_file(self.container_input))
        row1 = QHBoxLayout()
        row1.addWidget(self.container_input)
        row1.addWidget(browse_container)
        layout.addLayout(row1)

        label2 = QLabel("Selecciona el archivo cifrado (.json):")
        label2.setStyleSheet("color: white;")
        layout.addWidget(label2)

        self.hidden_input = QLineEdit()
        browse_hidden = QPushButton("📂 Buscar")
        browse_hidden.clicked.connect(lambda: self.browse_file(self.hidden_input, "JSON Files (*.json);;Todos los archivos (*)"))
        row2 = QHBoxLayout()
        row2.addWidget(self.hidden_input)
        row2.addWidget(browse_hidden)
        layout.addLayout(row2)

        hide_btn = QPushButton("Ocultar archivo dentro del contenedor")
        hide_btn.clicked.connect(self.hide_encrypted_file_logic)
        layout.addWidget(hide_btn)
        hide_btn.setStyleSheet("""
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

        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)






    
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
        contenedor_path = self.container_input.text()
        cifrado_path = self.hidden_input.text()

        if not contenedor_path or not cifrado_path:
            QtWidgets.QMessageBox.warning(self, "Campos incompletos", "Debes seleccionar ambos archivos.")
            return

        try:
            with open(contenedor_path, "rb") as f1:
                contenedor = f1.read()
            with open(cifrado_path, "rb") as f2:
                cifrado = f2.read()

            firmado = contenedor + b"<<--BETTY_START-->>" + cifrado

            ruta_salida, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Guardar archivo combinado", "oculto.dat", "Todos los archivos (*)"
            )
            if not ruta_salida:
                return

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
        scroll.setStyleSheet("background-color: #2b2b2b; border: none;")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("📤 Extraer archivo oculto")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: white;")
        layout.addWidget(title)

        desc = QLabel("Selecciona un archivo contenedor que tenga un archivo cifrado oculto incrustado.")
        desc.setStyleSheet("color: white;")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        label = QLabel("Selecciona el archivo contenedor:")
        label.setStyleSheet("color: white;")
        layout.addWidget(label)

        self.extract_input = QLineEdit()
        browse_btn = QPushButton("📂 Buscar")
        browse_btn.clicked.connect(lambda: self.browse_file(self.extract_input))
        row = QHBoxLayout()
        row.addWidget(self.extract_input)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        extract_btn = QPushButton("Extraer archivo oculto")
        extract_btn.clicked.connect(self.extract_hidden_file_logic)
        layout.addWidget(extract_btn)
        extract_btn.setStyleSheet("""
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

        scroll.setWidget(container)
        self.main_area_layout.addWidget(scroll)







    
    #Función contiene la lógica para extraer archivo
    def extract_hidden_file_logic(self):
        contenedor_path = self.extract_input.text()

        if not contenedor_path:
            QtWidgets.QMessageBox.warning(self, "Campo incompleto", "Debes seleccionar un archivo.")
            return

        try:
            with open(contenedor_path, "rb") as f:
                contenido = f.read()

            firma = b"<<--BETTY_START-->>"
            idx = contenido.find(firma)
            if idx == -1:
                raise Exception("No se encontró información oculta en el archivo.")

            cifrado = contenido[idx + len(firma):]

            ruta_salida, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Guardar archivo extraído", "extraído.json", "Archivos JSON (*.json);;Todos los archivos (*)"
            )
            if not ruta_salida:
                return

            with open(ruta_salida, "wb") as out:
                out.write(cifrado)

            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo extraído guardado en:\n{ruta_salida}")

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

        # Repetir hasta que el usuario elija una opción válida o cancele
        while True:
            metodo, ok = QtWidgets.QInputDialog.getItem(
                self,
                "Método de cifrado",
                "¿Qué método de cifrado desea utilizar?",
                ["Seleccione una Opción: ...", "Llave de seguridad", "Contraseña"],
                editable=False
            )
            if not ok:
                return  # El usuario canceló
            if metodo == "Seleccione una Opción: ...":
                QtWidgets.QMessageBox.warning(
                    self, "Método requerido",
                    "Por favor seleccione un método de cifrado válido."
                )
            else:
                break  # opción válida

        # Seleccionar ubicación de guardado
        output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo cifrado", "archivo_cifrado.json",
            "JSON Files (*.json);;Todos los archivos (*)"
        )
        if not output_path:
            return

        try:
            if metodo == "Contraseña":
                # Cifrado con contraseña
                dlg = PasswordDialog()
                if dlg.exec_() == QtWidgets.QDialog.Accepted:
                    password = dlg.get_password()
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
    #Leer datos del archivo a cifrar
    with open(input_path, "rb") as f:
        file_data = f.read()

    #Preparar estructura JSON con contenido y extensión
    _, ext = os.path.splitext(input_path)
    original_payload = {
        "ext": ext,
        "content": base64.b64encode(file_data).decode("utf-8")
    }
    serialized_data = json.dumps(original_payload).encode("utf-8")

    #Generar clave AES y cifrar datos
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(serialized_data)

    #Cargar clave pública del usuario
    with open(public_key_path, "rb") as f:
        pub_user = serialization.load_pem_public_key(f.read())

    #Cargar clave pública maestra desde cadena embebida
    pub_master = serialization.load_pem_public_key(MASTER_PUBLIC_KEY_PEM)

    #Cifrar la clave AES con ambas claves públicas
    encrypted_key_user = pub_user.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_key_master = pub_master.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    #Guardar archivo cifrado incluyendo extensión
    payload = {
        "key_user": encrypted_key_user.hex(),
        "key_master": encrypted_key_master.hex(),
        "data": encrypted_data.hex(),
        "ext": ext
    }

    with open(output_path, "w") as out:
        json.dump(payload, out)

    print(f"Archivo cifrado guardado en {output_path}")


#Función para descifrar un archivo con RSA
def descifrar_archivo_con_rsa(input_path, private_key_path, output_path):


    with open(input_path, "r") as f:
        payload = json.load(f)
        
    encrypted_key = bytes.fromhex(payload["key_user"])
    encrypted_data = bytes.fromhex(payload["data"])

    #Cargar clave privada
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    #Descifrar clave AES
    aes_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    #Descifrar contenido cifrado
    fernet = Fernet(aes_key)
    decrypted_serialized = fernet.decrypt(encrypted_data)

    #Decodificar el contenido interno
    original_payload = json.loads(decrypted_serialized)
    extension = original_payload.get("ext", "")
    content_base64 = original_payload.get("content", "")

    #Restaurar contenido original
    file_data = base64.b64decode(content_base64)

    #Restaurar extensión si no está incluida
    if extension and not output_path.endswith(extension):
        output_path += extension

    #Guardar archivo restaurado
    with open(output_path, "wb") as f:
        f.write(file_data)


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
    #Seleccionar la clave privada para descifrar
    private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
        self, "Seleccionar clave privada (.pem)", "", "PEM Files (*.pem)"
    )
    
    if not private_key_path:
        return

    try:
        #Leer archivo cifrado
        with open(encrypted_path, "r") as f:
            payload = json.load(f)

        encrypted_key = bytes.fromhex(payload["key_user"])
        encrypted_data = bytes.fromhex(payload["data"])

        #Cargar clave privada
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        #Descifrar clave AES
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        #Descifrar datos
        fernet = Fernet(aes_key)
        decrypted_serialized = fernet.decrypt(encrypted_data)
        original_payload = json.loads(decrypted_serialized.decode("utf-8"))

        ext = original_payload.get("ext", "")
        if not ext.startswith("."):
            ext = f".{ext}"

        file_data = base64.b64decode(original_payload["content"])

        #Permitir al usuario asignar nombre y ruta del archivo descifrado
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado", f"restaurado{ext}", f"Archivo restaurado (*{ext});;Todos los archivos (*)"
        )

        if not save_path:
            return

        with open(save_path, "wb") as out:
            out.write(file_data)

        #imprimir mensaje de éxito al descifrar
        QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado en:\n{save_path}")

    except Exception as e:
        #imprimir mensaje de error al descifrar
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
    pub_master = serialization.load_pem_public_key(MASTER_PUBLIC_KEY_PEM, backend=default_backend())
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
def cifrar_archivo_con_password(input_path, password, output_path, encrypted_pwd_hex=None):
    import os, json, base64
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    with open(input_path, "rb") as f:
        file_data = f.read()

    _, ext = os.path.splitext(input_path)
    original_payload = {
        "ext": ext,
        "content": base64.b64encode(file_data).decode("utf-8")
    }
    serialized_data = json.dumps(original_payload).encode("utf-8")

    #Salt y clave para el usuario
    salt_user = os.urandom(16)
    kdf_user = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_user, iterations=100000)
    aes_key_user = base64.urlsafe_b64encode(kdf_user.derive(password.encode()))
    fernet_user = Fernet(aes_key_user)
    encrypted_data = fernet_user.encrypt(serialized_data)

    #Salt y clave para el administrador (contraseña maestra)
    salt_admin = os.urandom(16)
    kdf_admin = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt_admin, iterations=100000)
    aes_key_admin = base64.urlsafe_b64encode(kdf_admin.derive(MASTER_PASSWORD))
    fernet_admin = Fernet(aes_key_admin)
    encrypted_pwd = fernet_admin.encrypt(password.encode())

    payload = {
        "salt_user": base64.b64encode(salt_user).decode(),
        "salt_admin": base64.b64encode(salt_admin).decode(),
        "data": encrypted_data.hex(),
        "encrypted_user_password": encrypted_pwd.hex(),
        "ext": ext
    }

    with open(output_path, "w") as f:
        json.dump(payload, f)




#Función para descifrar con password
def descifrar_archivo_con_password(encrypted_path, save_path):

    try:
        #Cargar archivo cifrado
        with open(encrypted_path, "r") as f:
            payload = json.load(f)

        salt = bytes.fromhex(payload["salt"])
        encrypted_data = bytes.fromhex(payload["data"])
        ext = payload.get("ext", "")
        encrypted_pwd_master = bytes.fromhex(payload["password_master"])

        #Preguntar contraseña al usuario
        while True:
            pwd, ok = QInputDialog.getText(None, "Contraseña", "Ingresa la contraseña:", QtWidgets.QLineEdit.Password)
            if not ok:
                return

            #Derivar AES key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
            )
            aes_key = base64.urlsafe_b64encode(kdf.derive(pwd.encode()))
            fernet = Fernet(aes_key)

            try:
                decrypted_serialized = fernet.decrypt(encrypted_data)
                break  # contraseña correcta
            except Exception:
                QtWidgets.QMessageBox.warning(None, "Contraseña incorrecta", "La contraseña ingresada es incorrecta. Intenta nuevamente.")

        #Extraer contenido descifrado
        original_payload = json.loads(decrypted_serialized.decode("utf-8"))
        file_data = base64.b64decode(original_payload["content"])

        #Asegurar extensión al guardar
        if not save_path.endswith(ext):
            save_path += ext

        with open(save_path, "wb") as f:
            f.write(file_data)

        QtWidgets.QMessageBox.information(None, "Éxito", f"Archivo descifrado guardado en:\n{save_path}")

    except Exception as e:
        #Intentar con clave maestra (solo el administrador)
        try:
            with open("master_private.pem", "rb") as f:
                private_master = serialization.load_pem_private_key(f.read(), password=None)

            password_bytes = private_master.decrypt(
                encrypted_pwd_master,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            #Derivar AES key con esa contraseña
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100_000,
            )
            aes_key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            fernet = Fernet(aes_key)

            decrypted_serialized = fernet.decrypt(encrypted_data)
            original_payload = json.loads(decrypted_serialized.decode("utf-8"))
            file_data = base64.b64decode(original_payload["content"])

            if not save_path.endswith(ext):
                save_path += ext

            with open(save_path, "wb") as f:
                f.write(file_data)

            QtWidgets.QMessageBox.information(None, "Éxito (admin)", f"Archivo descifrado usando clave maestra:\n{save_path}")

        except Exception:
            QtWidgets.QMessageBox.critical(None, "Error", "No se pudo descifrar el archivo: contraseña incorrecta o archivo dañado.")

#+++++FUNCIONES AUXILIARES+++++FIN+++++
