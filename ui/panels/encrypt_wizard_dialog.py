import os
import re
import json
import tempfile
import shutil
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QLabel, QPushButton, QFileDialog, QStackedLayout,
                             QListWidget, QListWidgetItem, QWidget, QHBoxLayout, QRadioButton,
                             QLineEdit, QProgressBar, QMessageBox, QCheckBox, QComboBox
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtGui import QDragEnterEvent, QDropEvent

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QListWidget,
    QLineEdit, QProgressBar, QMessageBox, QStackedLayout, QListWidgetItem
)
from ui.widgets.dropzone_widget import DropZoneWidget
from ui.utils.encryption_logic import encrypt_with_password, encrypt_with_public_key
from pathlib import Path
from db_cliente import get_client_uuid
from ui.utils.encryption_logic import encrypt_with_public_key
from ui.views.encrypted_view import EncryptedView

class EncryptWizardDialog(QDialog):
    def __init__(self, parent=None, client_uuid=None, encrypted_view=None, initial_files=None):
        super().__init__(parent)
        self.encrypted_view = encrypted_view
        self.client_uuid = client_uuid
        self.setWindowTitle("Asistente de cifrado")
        self.setMinimumWidth(540)
        self.setStyleSheet("background-color: #2b2b2b; color: white;")

        self.all_keys = []
        self.final_selected_key = None

        self.files_to_encrypt = []
        self.output_path = r"C:\\Users\\DEV_FARID\\Downloads\\Cifrado"
        self.selected_method = None

        self.layout = QVBoxLayout(self)
        self.stack = QStackedLayout()
        self.layout.addLayout(self.stack)

        self.setup_step1()
        self.setup_step2()
        self.setup_step3()

        #Agregar archivos predefinidos, agregados (notas por ejemplo)
        if initial_files:
            self.add_files(initial_files)

        #Contendor Botones (Atrás - Siguiente - Cancelar)
        self.buttons_layout = QHBoxLayout()
        self.btn_back = QPushButton("<<Atrás")
        self.btn_back.clicked.connect(self.prev_step)
        self.btn_next = QPushButton("Siguiente>>")
        self.btn_next.clicked.connect(self.next_step)
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.clicked.connect(self.reject)

        #Agregar los botones al layout principal
        self.buttons_layout.addWidget(self.btn_back)
        self.buttons_layout.addWidget(self.btn_next)
        self.buttons_layout.addWidget(self.btn_cancel)
        self.layout.addLayout(self.buttons_layout)

        self.current_step = 0
        self.stack.setCurrentIndex(self.current_step)
        self.update_button()
        
        
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
        add_folder_btn = QPushButton("📂Agregar carpeta")
        add_folder_btn.clicked.connect(self.add_folder)
        layout.addWidget(add_folder_btn)

        self.stack.addWidget(step)

    #Función agregar archivos desde notas
    def add_files(self, files):
        for file in files:
            if os.path.isfile(file) and file not in self.files_to_encrypt:
                self.files_to_encrypt.append(file)
                self.file_list.addItem(str(file))                  

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
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        #Contenedor fijo para el encabezado - Título
        header = QVBoxLayout()
        label = QLabel("Selecciona el método de cifrado:")
        label.setStyleSheet("font-weight: bold; color: white;")
        header.addWidget(label)

        # Descripción
        desc = QLabel(
            "Elije cómo deseas encriptar los archivos, puedes cifrar tus datos usando una llave o una contraseña segura. "
            "Ambos métodos protegen tu información para que solo tú o tus destinatarios puedan acceder a ella. "
            "La llave se genera automáticamente y ofrece un alto nivel de seguridad; "
            "tu eliges la contraseña, asegúrate de que sea fuerte y recuerda compartirla con tus destinatarios usando un canal seguro. "
            "Estos métodos garantizan confidencialidad, integridad y autenticación de los datos.\n\nTu privacidad está protegida, elijas el método que elijas."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #969595; font-size: 12px;")
        header.addWidget(desc)

        layout.addLayout(header)

        self.radio_password = QRadioButton("Contraseña")
        self.radio_key = QRadioButton("Llave pública")
        layout.addWidget(self.radio_password)
        layout.addWidget(self.radio_key)

        #Spacer empujar hacia arriba
        layout.addStretch()

        self.stack.addWidget(step)

    #Función paso 3
    def setup_step3(self):
        step = QWidget()
        layout = QVBoxLayout(step)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        #Contenedor fijo encabezado
        header = QVBoxLayout()
        label = QLabel("Encriptar")
        label.setStyleSheet("font-weight: bold; color: white;")
        layout.addWidget(label)

        # Descripción dinámica
        self.desc_step3 = QLabel("Estos métodos garantizan la confidencialidad, integridad y autenticación de los datos.")
        self.desc_step3.setWordWrap(True)
        self.desc_step3.setStyleSheet("color: #969595; font-size: 12px;")
        layout.addWidget(self.desc_step3)

        #Layout contenedor de campos dinámicos
        self.content_layout = QVBoxLayout()
        
        #Contenedor dinámico para formularo - Ingresar contraseña        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Contraseña")

        #Confirmar contraseña
        self.password_confirm = QLineEdit()
        self.password_confirm.setEchoMode(QLineEdit.Password)
        self.password_confirm.setPlaceholderText("Confirmar contraseña")

        #Barra de fortaleza de la contraseña
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)

        #Check mostrar contraseña
        self.show_password_checkbox = QCheckBox("Mostrar contraseña")
        self.show_password_checkbox.setStyleSheet("color: #CCCCCC; font-size: 12px; margin-top: 4px;")
        self.show_password_checkbox.stateChanged.connect(self.toggle_password_visibility)
        
        #Buscar llave
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Buscar llave...")
        self.search_bar.setStyleSheet("color: #CCCCCC; font-size: 12px;")
        self.search_bar.textChanged.connect(self.filter_keys)

        #ComboBox de llaves
        self.key_combo = QComboBox()
        self.key_combo.setStyleSheet("color: grey;")
        self.key_combo.setEditable(False)

        #Botones agregar/quitar
        btn_container = QWidget()
        key_btns = QHBoxLayout(btn_container)
        self.btn_add_key = QPushButton("Agregar")
        self.btn_remove_key = QPushButton("Quitar")
        self.btn_add_key.clicked.connect(self.add_selected_key)
        self.btn_remove_key.clicked.connect(self.remove_selected_key)
        key_btns.addWidget(self.btn_add_key)
        key_btns.addWidget(self.btn_remove_key)

        #Etiqueta llave seleccionada
        self.selected_key_label = QLabel("")
        self.selected_key_label.setStyleSheet("color: #90ee90; font-size: 12px;")

        #Agregar widgets al contenedor dinámico        
        self.content_layout.addWidget(self.password_input)
        self.content_layout.addWidget(self.password_confirm)
        self.content_layout.addWidget(self.show_password_checkbox)
        self.content_layout.addWidget(self.strength_bar)
        self.content_layout.addWidget(self.search_bar)
        self.content_layout.addWidget(self.key_combo)
        self.content_layout.addWidget(btn_container)
        self.content_layout.addWidget(self.selected_key_label)

        #Agregar al layour principal
        layout.addLayout(self.content_layout)

        #Spacer para empujar hacia arriba
        layout.addStretch()

        self.stack.addWidget(step)        

        self.password_input.textChanged.connect(self.evaluate_strength)

        #Leer llaves
        self.load_public_keys()

        
    
    #Función leer las llaves públicas
    def load_public_keys(self):
        keys_dir = r"C:\\Users\\DEV_FARID\\Downloads\\MisLlaves"
        self.all_keys = []

        self.key_combo.clear()
        self.key_combo.addItem("Selecciona una llave...")

        #Agregar ícono
        icon = QIcon("assets/icons/key-yellow.svg")

        if os.path.exists(keys_dir):
            for fname in os.listdir(keys_dir):
                if fname.endswith("_public.pem"):
                    self.all_keys.append(fname)
                    self.key_combo.addItem(icon, fname)
    
    #Función actualizar llaves
    def update_key_combo(self, keys):
        self.key_combo.clear()
        self.key_combo.addItems(keys)
    
    #Función filtrar - buscar llaves
    def filter_keys(self, text):
        filtered = [k for k in self.all_keys if text.lower() in k.lower()]
        self.key_combo.clear()
        self.key_combo.addItem("Selecciona una llave...")
        self.key_combo.addItems(filtered)
    
    #Funcion agregar llave seleccionada
    def add_selected_key(self):
        selected = self.key_combo.currentText()
        if selected == "Selecciona una llave...":
            QMessageBox.warning(self, "Seleccionar llave", "Por favor, selecciona una llave válida!")
            return
        self.final_selected_key = selected
        self.selected_key_label.setText(f"✅ Llave agregada: {selected}")
        self.selected_key_label.setStyleSheet("color: #90ee90; font-size: 12px;")
        
    
    #Función quitar llave seleccionada
    def remove_selected_key(self):
        self.final_selected_key = None        
        self.selected_key_label.setText("⚠️ Llave agregada: (ninguna)")
        self.selected_key_label.setStyleSheet("color: #ee9b90; font-size: 12px;")
        
        

    #Función evaluar la fortaleza de la contraseña
    def evaluate_strength(self, password):
        score = 0
        if len(password) >= 16:
            score += 25
        if re.search(r"[A-Z]", password):
            score += 20
        if re.search(r"[a-z]", password):
            score += 20
        if re.search(r"\d", password):
            score += 20
        if re.search(r"[!@¿#$%^&*(),.\":{}|<>]", password):
            score += 15
        
        self.strength_bar.setValue(score)

        #Cambiar color de la barra
        if score < 40:
            color = "red"
        elif score < 70:
            color = "yellow"
        else:
            color = "green"
        
        self.strength_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px; solid #444;
                text-align: right;
                color: white;
                background-color: #2e2e2e;
                height: 16pxx;
            }}
            QProgressBar::chunk {{
                border-radius: 6px;
                background: qlineargradient(
                x1: 0, y1: 0, x2: 1, y2: 0,
                stop: 0 {color},
                stop: 1 #1e1e1e
                );
                margin: 1px;
            }}
        """)

    #Función paso siguiente
    def next_step(self):
        if self.current_step == 0 and not self.files_to_encrypt:
            QMessageBox.warning(self, "Archivos requeridos", "Debes agregar al menos un archivo!")
            return
        if self.current_step == 1:
            if self.radio_password.isChecked():
                self.selected_method = "password"
            elif self.radio_key.isChecked():
                self.selected_method = "key"
            else:
                QMessageBox.warning(self, "Método requerido", "Debes seleccionar un método de cifrado para continuar.")
                return
        
        if self.current_step == 2:
            self.finalize_encryption()
            return
        
        self.current_step += 1
        self.stack.setCurrentIndex(self.current_step)
        self.update_button()
        if self.current_step == 2:
            self.show_correct_fields()
    
    #Función paso anterior
    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_button()

    #Función actualizar botón
    def update_button(self):
        self.btn_next.setText("Cifrar" if self.current_step == 2 else "Siguiente>>")
        self.btn_back.setEnabled(self.current_step > 0)
        
            
    #Función motrar/ocultar metodo cifrado según selección usuario
    def show_correct_fields(self):
        if self.selected_method == "password":
            self.desc_step3.setText(
                "Tus archivos se protegerán con una contraseña segura: Solo quienes conozcan esta contraseña podrán acceder a la información cifrada. "
                "Asegúrate de compartirla por un medio confiable. Esta opción combina simplicidad con una excelente protección si eliges una contraseña fuerte. "
                "\n\nTu contraseña debe tener 8 caracteres como mínimo e incluir números y caracteres especiales."
            )                      
            self.password_input.show()
            self.password_confirm.show()
            self.strength_bar.show() 
            self.show_password_checkbox.show()
            self.selected_key_label.hide()   
            self.key_combo.hide()
            self.search_bar.hide()
            self.btn_add_key.hide()
            self.btn_remove_key.hide()                               
        elif self.selected_method == "key":
            self.desc_step3.setText(
                "Tus archivos se cifrarán utilizando un sistema de laves criptográficas asimétricas: "
                "La información se protege con una llave pública y solo puede descifrarse con su correspondiente llave privada, lo que garantiza un nivel de seguridad robusto, "
                "ideal para compartir tus archivos de forma segura incluiso en canales abiertos."
                "\n\nAgrega una llave pública:"
            )            
            self.password_input.hide()
            self.password_confirm.hide()
            self.strength_bar.hide()           
            self.show_password_checkbox.hide()
            self.selected_key_label.show()
            self.key_combo.show()
            self.search_bar.show()
            self.btn_add_key.show()
            self.btn_remove_key.show()
        
    #Función finalizar proceso cifrado
    def finalize_encryption(self):
        if self.radio_password.isChecked():
            pwd = self.password_input.text()
            confirm = self.password_confirm.text()

            if pwd != confirm:
                QMessageBox.warning(self, "Contraseña", "las contraseñas no coinciden")
                return
            
            if len(pwd) < 6:
                QMessageBox.warning(self, "Contraseña", "La contraseña es demasiado corta")
                return
            self.perform_encrypt_with_password(pwd)
        
        elif self.radio_key.isChecked():
            if not getattr(self, "final_selected_key", None):
                QMessageBox.warning(self, "Llave requerida", "Debes agregar una llave pública!")
                return
            self.perform_encrypt_with_key(self.final_selected_key)
        
        
    
    #Función ver/ocultar contraseña
    def toggle_password_visibility(self, state):
        mode = QLineEdit.Normal if state == Qt.Checked else QLineEdit.Password
        self.password_input.setEchoMode(mode)
        self.password_confirm.setEchoMode(mode)

    #Función para llamar cifrado con contraseña
    def perform_encrypt_with_password(self, password):
        for filepath in self.files_to_encrypt:
            try:
                result = encrypt_with_password(filepath, password, client_uuid="desktop-client")
                print(f"[✔] Archivo cifrado con contraseña: {result}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo cifrar {filepath}:\n{str(e)}")
        
        #Refrescar lista de archivos en el panel de cifrado
        #Recargar lista de archivos en el panel de cifrado
        if self.encrypted_view:
            self.encrypted_view.load_files()
        
        QMessageBox.information(self, "Éxito", "Archivo(s) cifrado(s) correctamente!")
        self.accept()


    #Función para llamar cifrado con llave
    def perform_encrypt_with_key(self, key_filename):
        try:
            keys_dir = Path(r"C:\Users\DEV_FARID\Downloads\MisLlaves") #Temporal CAMBIAR antes de compilar
            keys_dir.mkdir(parents=True, exist_ok=True)
            key_path = keys_dir / key_filename

            #Validar que exista la llave
            if not key_path.exists():
                QMessageBox.critical(self, "Error", f"No se encontró la llave:\n{key_path}")
                return
            
            #Validar extención de la llave .pem
            if not key_path.suffix.lower() == ".pem":
                QMessageBox.critical(self, "Error", "El archivo seleccionado no es un llave válida")
                return
            
            #Leer el contenido
            with open(key_path, 'r', encoding='utf-8') as f:
                public_key_pem = f.read()
            
            #Validar contenido
            if "-----BEGIN RSA PUBLIC KEY-----" not in public_key_pem:
                QMessageBox.critical(self, "Error", "El archivo no contiene una llave RSA válida")
                return
            
        except Exception as e:
            QMessageBox.critical(self, "Error", "No se pudo leer la llave:\n{str(e)}")
            return
        
        #Intentar cifrar los archivos
        for filepath in self.files_to_encrypt:
            try:
                encrypt_with_public_key(filepath, public_key_pem, self.client_uuid)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo cifrar {filepath}:\n{str(e)}")
                return
        
        #Recargar lista de archivos en el panel de cifrado
        if self.encrypted_view:
            self.encrypted_view.load_files()
        
        QMessageBox.information(self, "Éxito", "Archivo(s) cifrado(s) correctamente!")
        self.accept()

               

    #Función para construir payload con archivos a cifrar
    def build_payload(self):
        payload = {"files": {}}
        for path in self.files_to_encrypt:
            name = os.path.basename(path)
            with open(path, "rb") as f:
                payload["files"][name] = f.read().hex()
        return payload