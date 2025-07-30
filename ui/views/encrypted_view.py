
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QLineEdit, QPushButton, QMenu, QAction, QFileDialog, QMessageBox, QSizePolicy, QStackedLayout
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QIcon, QPixmap, QPainter, QColor
from pathlib import Path
import os, shutil, datetime

class EncryptedView(QWidget):
    def __init__(self):
        super().__init__()
        self.cifrados_dir = Path(r"C:\Users\DEV_FARID\Downloads\Cifrado")
        self.extraidos_dir = Path(r"C:\Users\DEV_FARID\Downloads\Extraido")

        self.layout = QVBoxLayout(self)
        self.setLayout(self.layout)

        #Barra búsqueda de archivos
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Buscar archivo...")
        self.search_bar.textChanged.connect(self.filter_files)
        self.layout.addWidget(self.search_bar)

        #Layout para listar archivos cifrados y extraidos        
        self.lista_cifrados = QListWidget()
        self.lista_extraidos = QListWidget()
        

        # Contenedor con título para lista de cifrados
        cifrados_layout = QVBoxLayout()
        cifrados_title = QLabel("📄 Mis archivos")
        cifrados_title.setStyleSheet("color: white; font-size: 14px; font-weight: bold; margin-bottom: 6px;")
        cifrados_title.setAlignment(Qt.AlignCenter)
        cifrados_layout.addWidget(cifrados_title)
        cifrados_layout.addWidget(self.lista_cifrados)
        cifrados_layout.addStretch()

        # Contenedor con título para lista de extraídos
        extraidos_layout = QVBoxLayout()
        extraidos_title = QLabel("📄 Recibidos")
        extraidos_title.setStyleSheet("color: white; font-size: 14px; font-weight: bold; margin-bottom: 6px;")
        extraidos_title.setAlignment(Qt.AlignCenter)
        extraidos_layout.addWidget(extraidos_title)
        extraidos_layout.addWidget(self.lista_extraidos)
        extraidos_layout.addStretch()

        #Contenedor para ambas listas (Mis Archivos - Recibidos)
        self.files_container = QWidget()
        files_container_layout = QHBoxLayout(self.files_container)
        files_container_layout.addLayout(cifrados_layout)
        files_container_layout.addLayout(extraidos_layout)      

        #Dar formato a lista
        for lista in [self.lista_cifrados, self.lista_extraidos]:
            lista.setStyleSheet("""
                QListWidget {
                    background: transparent;
                    color: white;
                    border: none;
                }
                QListWidget::item:selected {
                    background-color: #3c3c3c;
                    border-radius: 6px;
                }
                QListWidget::item:hover {
                background-color: #4a4a4a;
                border-radius: 6px;
                }
            """)
        
        #Mensaje de búsqueda vacía
        self.empty_widget = QWidget()
        empty_layout = QVBoxLayout(self.empty_widget)
        empty_layout.setAlignment(Qt.AlignCenter)
        empty_layout.addStretch()

        #Ícono de búsqueda vacía
        icon_label = QLabel()
        icon_pixmap = QPixmap("assets/icons/search_empty.svg")
        if not icon_pixmap.isNull():
            colored_pixmap = QPixmap(icon_pixmap.size())
            colored_pixmap.fill(Qt.transparent)

            painter = QPainter(colored_pixmap)
            painter.setCompositionMode(QPainter.CompositionMode_Source)
            painter.drawPixmap(0, 0, icon_pixmap)
            painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
            painter.fillRect(colored_pixmap.rect(), QColor("#AAAAAA"))
            painter.end()

            scaled_pixmap = colored_pixmap.scaled(115, 115, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            icon_label.setPixmap(scaled_pixmap)
            icon_label.setAlignment(Qt.AlignCenter)
            icon_label.setStyleSheet("margin-bottom: 10px;")
        
        #Mensaje busqueda vacía
        text_label = QLabel("No hay resultados sobre tu búsqueda. Revisa tu ortografía o intenta buscar algo distinto.")
        text_label.setStyleSheet("color: #AAAAAA; font-size: 12px;")
        text_label.setAlignment(Qt.AlignCenter)
        text_label.setWordWrap(True)
        

        #Agregar widgets
        empty_layout.addWidget(icon_label, alignment=Qt.AlignCenter)
        empty_layout.addWidget(text_label)
        

        #Layout apilado de contenido y mensaje vacío
        self.stack_layout = QStackedLayout()
        self.layout.addLayout(self.stack_layout)
        self.stack_layout.addWidget(self.files_container)
        self.stack_layout.addWidget(self.empty_widget)      

        #Llamar el metodo load_files()
        self.load_files()

    #Función leer los archivos cifrados y extraidos
    def load_files(self):
        self.lista_cifrados.clear()
        self.lista_extraidos.clear()
        cifrados = self.get_files(self.cifrados_dir)
        extraidos = self.get_files(self.extraidos_dir)
        if not (cifrados or extraidos):
            self.stack_layout.setCurrentWidget(self.empty_widget)
        else:
            self.stack_layout.setCurrentWidget(self.files_container)

        for path in extraidos:
            self.add_item(self.lista_extraidos, path)
        
        for path in cifrados:
            self.add_item(self.lista_cifrados, path)
    
    #Función para obtener los archivos desde el directorio donde se almacenan
    def get_files(self, directory):
        if not directory.exists(): return []
        return sorted([f for f in directory.iterdir() if f.is_file()], key=os.path.getmtime, reverse=True)
    
    #Función para agregar archivos a la lista
    def add_item (self, lista, filepath):
        item = QListWidgetItem()
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(8, 4, 8, 4)
        
        #Agregar icono a la lista de archivos
        icon = QLabel()
        icon.setPixmap(QPixmap("assets/icons/encrypted.svg").scaled(24, 24, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        layout.addWidget(icon)

        #Agregar nombre del archivo a la lista
        label = QLabel(filepath.name)
        label.setStyleSheet("color: white; font-size: 13px;")
        label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        label.setWordWrap(False)
        label.setMinimumWidth(200)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(label, stretch=2)

        #Agregar la fecha de creación del archivo a la lista
        #date = QLabel(datetime.datetime.fromtimestamp(filepath.stat().st_mtime).strftime("%d/%m/%Y %H:%M"))
        #date.setStyleSheet("color: #CCCCCC; font-size: 12px")       
        #layout.addWidget(date)

        #Menú de opciones para cada archivo (Descifrar/Ocultar/Exportar/Eliminar)
        menu_btn = QPushButton("⋮")
        menu_btn.setFixedSize(28, 28)
        menu_btn.setStyleSheet("background: transparent; color: white; font-size: 18px;")
        menu = QMenu()
        menu.addAction("🔐 Descifrar", lambda: self.descifrar_archivo(filepath))
        menu.addAction("📦 Ocultar", lambda: self.ocultar_archivo(filepath))
        menu.addAction("📁 Exportar", lambda: self.exportar_archivo(filepath))
        menu.addAction("🗑 Eliminar", lambda: self.eliminar_archivo(filepath))
        menu_btn.clicked.connect(lambda: menu.exec_(menu_btn.mapToGlobal(menu_btn.rect().bottomLeft())))
        layout.addWidget(menu_btn)

        #Agregar item a la lista
        widget.setLayout(layout)
        item.setSizeHint(widget.sizeHint())
        lista.addItem(item)
        lista.setItemWidget(item, widget)

        item.setSizeHint(QSize(0, 48))
    
    #Función para filtrar archivos
    def filter_files(self, keyword):
        matches = 0
        for lista in [self.lista_cifrados, self.lista_extraidos]:
            for i in range(lista.count()):
                item = lista.item(i)
                widget = lista.itemWidget(item)
                if widget:
                    labels = widget.findChildren(QLabel)
                    filename = labels[1].text() if len(labels) > 1 else ""
                    visible = keyword.lower() in filename.lower()
                    item.setHidden(not visible)
                    if visible:
                        matches += 1
        self.stack_layout.setCurrentWidget(self.empty_widget if matches == 0 else self.files_container)
    
    #Función para llamar el método para descifrar
    def descifrar_archivo(self, path): print(f"Descifrar: {path}")
    #Función para llamar el método para ocultar
    def ocultar_archivo(self, path): print(f"Ocultar: {path}")
    #Función para exportar un archivo
    def exportar_archivo(self, path):
        dest, _ = QFileDialog.getSaveFileName(self, "Exportar archivo", path.name)
        if dest:
            shutil.copy(str(path), dest)
            QMessageBox.information(self, "Exportado", f"Archivo exportado a:\n{dest}")
    #Función para eliminar un archivo de la lista
    def eliminar_archivo(self, path):
        confirm = QMessageBox.question(self, "Eliminar", f"¿Eliminar {path.name}?", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            path.unlink()
            self.load_files()