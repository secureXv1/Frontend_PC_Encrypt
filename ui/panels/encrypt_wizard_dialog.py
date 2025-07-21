import os
import json
import tempfile
import shutil
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLabel, QPushButton, QFileDialog, QStackedLayout,
                             QListWidget, QListWidgetItem, QWidget, QHBoxLayout, QRadioButton,
                             QLineEdit, QProgressBar, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtGui import QDragEnterEvent, QDropEvent

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QListWidget,
    QLineEdit, QProgressBar, QMessageBox, QStackedLayout, QListWidgetItem
)
from ui.widgets.dropzone_widget import DropZoneWidget

class EncryptWizardDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Asistente de cifrado")
        self.setMinimumWidth(540)
        self.setStyleSheet("background-color: #1e1e1e; color: white;")

        self.files_to_encrypt = []
        self.output_path = r"C:\\Users\\DEV_FARID\\Downloads\\Cifrado"

        self.layout = QVBoxLayout(self)
        self.stack = QStackedLayout()
        self.layout.addLayout(self.stack)

        self.setup_step1()
        self.setup_step2()
        self.setup_step3()

        #Contenedor de botones
        btn_layout = QHBoxLayout()
        btn_layout.setContentsMargins(10, 20, 10, 20)

        #Botón Atrás
        self.btn_back = QPushButton("<Atrás")
        self.btn_back.clicked.connect(self.prev_step)
        btn_layout.addWidget(self.btn_back)#Lo agrega al contenedor

        #Botón siguiente
        self.btn_next = QPushButton("Siguiente>")
        self.btn_next.clicked.connect(self.next_step)
        btn_layout.addWidget(self.btn_next)#Lo agrega al contenedor

        #Botón cancelar
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)#Lo agrega al contenedor

        self.layout.addLayout(btn_layout)

        self.current_step = 0
        self.stack.setCurrentIndex(self.current_step)
        self.update_button()
    
    #Función paso anterior
    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_button()
    
    #Función actualizar botón
    def update_button(self):
        self.btn_next.setText("Cifrar" if self.current_step == 2 else "Siguiente>")
        self.btn_back.setEnabled(self.current_step > 0)

    #Función paso 1
    def setup_step1(self):
        step = QWidget()
        layout = QVBoxLayout(step)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        #Título
        label = QLabel("Selecciona archivos o carpetas para cifrar:")
        label.setStyleSheet("font-weight: bold; color: white;")
        layout.addWidget(label)

        # Descripción
        desc = QLabel("Este asistente te permitirá asegurar archivos y carpetas para almacenar o transferir de manera segura. Arrastra y coloca los archivos o navega hasta seleccionarlos.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #969595; font-size: 12px;")
        layout.addWidget(desc)

        #Drop área
        drop_area = DropZoneWidget(self.add_files_from_paths)
        drop_area.setMinimumHeight(130)
        layout.addWidget(drop_area)

        #Formato para lista de archivos
        self.file_list = QListWidget()
        self.file_list.setStyleSheet("color: white;")
        layout.addWidget(self.file_list)

        #Agregar carpeta
        add_folder_btn = QPushButton("Agregar carpeta")
        add_folder_btn.clicked.connect(self.add_folder)
        layout.addWidget(add_folder_btn)

        self.stack.addWidget(step)

    #Función para agregar carpeta a cifrar
    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")
        if folder:
            self.add_folder_from_path(folder)

    #Función agregar carpeta desde el path
    def add_folder_from_path(self, folder):
        for root, _, files in os.walk(folder):
            for file in files:
                full_path = os.path.join(root, file)
                self.add_file_to_list(full_path)

    #Función agregar archivos a la lista
    def add_file_to_list(self, filepath):
        if filepath not in self.files_to_encrypt:
            self.files_to_encrypt.append(filepath)
            self.file_list.addItem(filepath)

    #Función agregar archivos desde el path
    def add_files_from_paths(self, paths):
        for path in paths:
            self.add_file_to_list(path)

    #Función paso 2
    def setup_step2(self):
        step = QWidget()
        layout = QVBoxLayout(step)

        #Título
        label = QLabel("Selecciona el método de cifrado:")
        layout.addWidget(label)

        # Descripción
        desc = QLabel("Elije cómo deseas encriptar los archivos, usa una llevé ública de tus destinatarios (Recomendado: proporciona un nivel de seguridad más alto), o cifra los archivos con una contraseña segura (Recuerda: Debes compartir la contraseña con todos los destinatarios).")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #969595; font-size: 12px;")
        layout.addWidget(desc)

        self.radio_password = QRadioButton("Contraseña")
        self.radio_key = QRadioButton("Llave pública")
        layout.addWidget(self.radio_password)
        layout.addWidget(self.radio_key)

        self.stack.addWidget(step)

    #Función paso 3
    def setup_step3(self):
        step = QWidget()
        layout = QVBoxLayout(step)

        #Título
        label = QLabel("Encriptar")
        label.setStyleSheet("font-weight: bold; color: white;")
        layout.addWidget(label)

        # Descripción
        desc = QLabel("Editar mensaje metodo de cifrado.")
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #969595; font-size: 12px;")
        layout.addWidget(desc)

        #Ingresar contraseña
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Contraseña")

        #Confirmar contraseña
        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.Password)
        self.password_confirm.setPlaceholderText("Confirmar contraseña")

        #Definir rango de fortaleza de la contraseña
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)

        #Leer las llaves públicas
        self.public_key_list = QListWidget()
        self.load_public_keys()

        #Agregar al layout
        layout.addWidget(QLabel("Llena el campo correspondiente según el método seleccionado:"))
        layout.addWidget(self.password_input)
        layout.addWidget(self.password_confirm)
        layout.addWidget(self.strength_bar)
        layout.addWidget(self.public_key_list)

        self.password_input.textChanged.connect(self.evaluate_strength)

        self.stack.addWidget(step)
    
    #Función leer las llaces públicas
    def load_public_keys(self):
        keys_dir = r"C:\\Users\\DEV_FARID\\Downloads\\MisLlaves"
        self.public_key_list.clear()
        if os.path.exists(keys_dir):
            for fname in os.listdir(keys_dir):
                if fname.endswith("_public.pem"):
                    self.public_key_list.addItem(fname)

    #Función evaluar la fortaleza de la contraseña
    def evaluate_strength(self, text):
        length = len(text)
        score = 25 if length > 12 else (length * 2)
        self.strength_bar.setValue(score)

    def next_step(self):
        if self.current_step == 0 and not self.files_to_encrypt:
            QMessageBox.warning(self, "Archivos requeridos", "Debes agregar al menos un archivo.")
            return
        if self.current_step == 1 and not (self.radio_password.isChecked() or self.radio_key.isChecked()):
            QMessageBox.warning(self, "Método requerido", "Debes seleccionar un método de cifrado.")
            return
        if self.current_step == 2:
            self.finalize_encryption()
            return

        self.current_step += 1
        self.stack.setCurrentIndex(self.current_step)
        self.update_button()

    def update_button(self):
        self.btn_next.setText("Cifrar" if self.current_step == 2 else "Siguiente>")

    def finalize_encryption(self):
        if self.radio_password.isChecked():
            pwd = self.password_input.text()
            confirm = self.password_confirm.text()
            if pwd != confirm:
                QMessageBox.warning(self, "Contraseña", "Las contraseñas no coinciden")
                return
            if len(pwd) < 6:
                QMessageBox.warning(self, "Contraseña", "La contraseña es demasiado corta")
                return
            self.encrypt_with_password(pwd)

        elif self.radio_key.isChecked():
            selected = self.public_key_list.currentItem()
            if not selected:
                QMessageBox.warning(self, "Llave requerida", "Debes seleccionar una llave pública")
                return
            key_name = selected.text()
            keys_dir = r"C:\\Users\\DEV_FARID\\Downloads\\MisLlaves"
            key_path = os.path.join(keys_dir, key_name)
            self.encrypt_with_key(key_path)

        self.accept()

    def encrypt_with_password(self, password):
        payload = self.build_payload()
        print(f"[Cifrado] Archivos: {list(payload['files'].keys())}\nPassword: {password}")

    def encrypt_with_key(self, key_path):
        payload = self.build_payload()
        print(f"[Cifrado] Archivos: {list(payload['files'].keys())}\nKey path: {key_path}")

    def build_payload(self):
        payload = {"files": {}}
        for path in self.files_to_encrypt:
            name = os.path.basename(path)
            with open(path, "rb") as f:
                payload["files"][name] = f.read().hex()
        return payload