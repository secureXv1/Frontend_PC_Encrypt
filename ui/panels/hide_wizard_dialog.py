import os
from pathlib import Path
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, QFileDialog, QStackedLayout,
    QWidget, QHBoxLayout, QLineEdit, QMessageBox
)
from PyQt5.QtCore import Qt
from ui.widgets.dropzone_widget import DropZoneWidget

class HideWizardDialog(QDialog):
    def __init__(self, parent=None, encrypted_file_path=None):
        super().__init__(parent)
        self.encrypted_file_path = Path(encrypted_file_path)
        self.container_file_path = None
        self.save_file_path = None

        self.setWindowTitle("Asistente para ocultar archivo")
        self.setMinimumWidth(540)
        self.setStyleSheet("background-color: #2b2b2b; color: white;")

        self.layout = QVBoxLayout(self)
        self.stack = QStackedLayout()
        self.layout.addLayout(self.stack)

        self.setup_step1()
        self.setup_step2()

        # Botones inferiores
        self.buttons_layout = QHBoxLayout()
        self.btn_back = QPushButton("<< Atrás")
        self.btn_back.clicked.connect(self.prev_step)
        self.btn_next = QPushButton("Siguiente >>")
        self.btn_next.clicked.connect(self.next_step)
        self.btn_next.setEnabled(False)       
        self.btn_cancel = QPushButton("Cancelar")
        self.btn_cancel.clicked.connect(self.reject)

        self.buttons_layout.addWidget(self.btn_back)
        self.buttons_layout.addWidget(self.btn_next)
        self.buttons_layout.addWidget(self.btn_cancel)
        self.layout.addLayout(self.buttons_layout)

        self.current_step = 0
        self.stack.setCurrentIndex(self.current_step)
        self.update_buttons()

    def setup_step1(self):
        step = QWidget()
        layout = QVBoxLayout(step)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        label = QLabel("Selecciona el archivo contenedor (PDF, PNG, JPG):")
        label.setStyleSheet("font-weight: bold; color: white;")
        layout.addWidget(label)

        self.drop_area = DropZoneWidget(self.on_container_dropped)
        self.drop_area.setMinimumHeight(150)        
        self.drop_area.text_label.setText("Arrastra aquí tu archivo contenedor o haz clic para buscarlo")
        layout.addWidget(self.drop_area)

        self.container_label = QLabel("Archivo contenedor: no seleccionado")
        self.container_label.setStyleSheet("font-weight: bold; color: gray;")
        layout.addWidget(self.container_label)

        self.stack.addWidget(step)

    def setup_step2(self):
        step = QWidget()
        layout = QVBoxLayout(step)
        layout.setContentsMargins(30, 30, 30, 30)

        label = QLabel("Selecciona la ubicación donde se guardará el archivo oculto:")
        label.setStyleSheet("font-weight: bold; color: white;")
        layout.addWidget(label)

        self.output_path_input = QLineEdit()
        self.output_path_input.setPlaceholderText("Ruta donde se guardará el archivo oculto")
        layout.addWidget(self.output_path_input)

        browse_btn = QPushButton("📂 Buscar carpeta...")
        browse_btn.clicked.connect(self.browse_save_path)
        layout.addWidget(browse_btn)

        self.stack.addWidget(step)

    #Función para seleccionar contendor
    def on_container_dropped(self, paths):
        if not paths or len(paths) != 1:
            QMessageBox.warning(self, "Error", "Solo puedes incluir un único archivo contenedor.\nInténtalo nuevamente!")
            return
        file_path = Path(paths[0])
        if file_path.suffix.lower() not in [".pdf", ".jpg", ".jpeg", ".png", ".docx", ".doc", ".gif", ".xlsx", ".pptx"]:
            QMessageBox.warning(self, "Archivo inválido", "Selecciona un archivo contenedor válido (PDF, JPG, PNG)")
            return
        self.container_file_path = file_path
        self.container_label.setText(f"Archivo contenedor seleccionado: {file_path.name}")
        self.btn_next.setEnabled(True)

    #Función buscar el directorio para guardar archivo
    def browse_save_path(self):
        folder = QFileDialog.getExistingDirectory(self, "Seleccionar carpeta")
        if folder and self.container_file_path:            
            ext = self.container_file_path.suffix
            output_path = Path(folder) / self.container_file_path.name
            self.save_file_path = output_path
            self.output_path_input.setText(str(output_path))

    #Función paso siguiente 
    def next_step(self):
        if self.current_step == 0:
            if not self.container_file_path:
                QMessageBox.warning(self, "Contenedor requerido", "Debes seleccionar un archivo contenedor válido!")
                return


        if self.current_step == 1:
            self.perform_hide()
            return
        
        self.current_step += 1
        self.stack.setCurrentIndex(self.current_step)
        self.update_buttons()

    #Función paso previo
    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.stack.setCurrentIndex(self.current_step)
            self.update_buttons()

    #Función actualizar botones
    def update_buttons(self):
        self.btn_back.setEnabled(self.current_step > 0)
        self.btn_next.setText("Ocultar" if self.current_step == 1 else "Siguiente >>")

    #Ocultar archivo
    def perform_hide(self):
        if not self.container_file_path or not self.save_file_path:
            QMessageBox.warning(self, "Faltan datos", "Debes seleccionar un contenedor y una ubicación de guardado")
            return

        try:
            with open(self.container_file_path, "rb") as cont_f, open(self.encrypted_file_path, "rb") as enc_f:
                cont_data = cont_f.read()
                enc_data = enc_f.read()

            #Delimitador con el nombre el archivo cifrado incluido
            delimiter = f"<<--BETTY_START:{self.encrypted_file_path.name}-->>".encode()
            result = cont_data + delimiter + enc_data

            #Guardar archivo
            with open(self.save_file_path, "wb") as f:
                f.write(result)

            QMessageBox.information(self, "Éxito", f"Archivo ocultado exitosamente en:\n{self.save_file_path}")
            self.accept()

        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo ocultar el archivo: {str(e)}")