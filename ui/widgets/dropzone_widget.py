from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QFileDialog
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QDragEnterEvent, QDropEvent
import os

#Clase Drag and Drop
class DropZoneWidget(QWidget):
    def __init__(self, on_files_dropped):
        super().__init__()
        self.on_files_dropped = on_files_dropped

        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet("""
            QWidget {
                background-color: transparent;
                color: #aaa;
                border: 2px dashed #5a5a5a;
                border-radius: 10px;
                padding: 50px;
                font-size: 13px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        #Mensaje en el campo para Drag and Drop
        self.text_label = QLabel("Arrastra aquí tus archivos o haz clic para buscarlos")
        self.text_label.setAlignment(Qt.AlignCenter)
        self.text_label.setStyleSheet("color: #CCCCCC; font-weight: bold; font-size: 13px; margin-top: 8px;")

        #Agregamos al layout
        layout.addWidget(self.text_label)
    
    #Función Drag
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
    
    #Función Drop
    def dropEvent(self, event: QDropEvent):
        paths = []
        for url in event.mimeData().urls():
            local_path = url.toLocalFile()
            if os.path.isdir(local_path):
                for root, _, files in os.walk(local_path):
                    for file in files:
                        paths.append(os.path.join(root, file))
            
            else:
                paths.append(local_path)
        self.on_files_dropped(paths)
    
    #Función para seleccionar archivos a cifrar
    def mousePressEvent(self, event):
        files, _ = QFileDialog.getOpenFileNames(self, "Seleccionar archivos")
        if files:
            self.on_files_dropped(files)
