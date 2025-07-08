import os
import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton,
    QLabel, QLineEdit, QListWidgetItem, QDialog, QTextEdit, QMessageBox
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QFont, QPixmap, QPainter, QColor
from PyQt5.QtWidgets import QSizePolicy


class NotesView(QWidget):
    def __init__(self, notes_dir="NotasApp"):
        super().__init__()
        self.notes_dir = os.path.join(os.path.expanduser("~"), notes_dir)
        os.makedirs(self.notes_dir, exist_ok=True)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # ➕ Botón nueva nota
        self.new_button = QPushButton("➕ Nueva Nota")
        self.new_button.clicked.connect(self.create_note)
        self.layout.addWidget(self.new_button)

        # 🔍 Barra de búsqueda
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Buscar nota...")
        self.search_bar.textChanged.connect(self.filter_notes)
        self.layout.addWidget(self.search_bar)

        # 📄 Lista de notas
        self.list_widget = QListWidget()

        # Widget de mensaje vacío
        self.empty_widget = QWidget()
        empty_layout = QVBoxLayout(self.empty_widget)
        empty_layout.setAlignment(Qt.AlignCenter)

        # Ícono de búsqueda vacía
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
            icon_label.setStyleSheet("margin-bottom: 10px;")  # Espacio entre ícono y texto
            

        # Mensaje de texto
        text_label = QLabel("No hay resultados sobre tu búsqueda. Revisa tu ortografía o intenta buscar algo distinto")
        text_label.setStyleSheet("color: #AAAAAA; font-size: 12px;")
        text_label.setAlignment(Qt.AlignCenter)
        text_label.setWordWrap(True)

        # Agregar widgets
        empty_layout.addWidget(icon_label, alignment=Qt.AlignHCenter)
        empty_layout.addWidget(text_label)

        # Agregar al layout Principal
        self.empty_widget.setVisible(False)
        self.layout.addWidget(self.empty_widget)

        # Oculto por defecto
        self.empty_widget.setVisible(False)
        self.layout.addWidget(self.empty_widget)

        # ✅ Aplicar estilo para eliminar sombreado azul
        self.list_widget.setStyleSheet("""
            QListWidget::item:selected {
                background: transparent;
                border: none;
            }
            QListWidget::item {
                border: none;
                padding: 0px;
            }
        """)

        self.layout.addWidget(self.list_widget)        

        self.notes_data = []  # (filename, modified, content)
        self.load_notes()


    def load_notes(self):
        self.list_widget.clear()
        self.notes_data = []
        for filename in os.listdir(self.notes_dir):
            path = os.path.join(self.notes_dir, filename)
            if os.path.isfile(path) and filename.endswith(".txt"):
                modified = os.path.getmtime(path)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self.notes_data.append((filename, modified, content))
        self.notes_data.sort(key=lambda x: x[1], reverse=True)
        self.render_notes(self.notes_data)

    #Función visualización de las notas creadas
    def render_notes(self, notes_data):
        self.list_widget.clear()
        self.empty_widget.setVisible(False)
        if not notes_data:
            self.empty_widget.setVisible(True)
            return
        for filename, modified, content in notes_data:
            item = QListWidgetItem()
            item.setFlags(Qt.ItemIsEnabled)

            # Contenedor principal
            widget = QWidget()
            main_layout = QHBoxLayout()
            main_layout.setContentsMargins(16, 8, 16, 8)
            main_layout.setSpacing(18)

            # 🗒 Ícono
            icon_label = QLabel()
            icon_path = "assets/icons/notas.svg"
            if os.path.exists(icon_path):
                pixmap = QPixmap(icon_path)
                if not pixmap.isNull():
                    pixmap = pixmap.scaled(32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation)
                    icon_label.setPixmap(pixmap)
            icon_label.setFixedSize(70, 70)
            icon_label.setStyleSheet("background: none; border: none;")
            main_layout.addWidget(icon_label)

            # 📝 Título y fecha (sin bordes)
            text_container = QWidget()
            text_container.setStyleSheet("background: none; border: none;")
            text_layout = QVBoxLayout()
            text_layout.setContentsMargins(0, 0, 0, 0)
            text_layout.setSpacing(2)

            title_label = QLabel(filename.replace(".txt", ""))
            title_label.setStyleSheet("color: white; font-size: 15px; font-weight: bold; background: none; border: none;")
            title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            title_label.setWordWrap(False)
            title_label.setMinimumWidth(0)
            date_label = QLabel(datetime.datetime.fromtimestamp(modified).strftime("%d/%m/%Y %H:%M"))
            date_label.setStyleSheet("color: #BBBBBB; font-size: 11px; background: none; border: none;")

            text_layout.addWidget(title_label)
            text_layout.addWidget(date_label)
            text_container.setLayout(text_layout)            
            main_layout.addWidget(text_container, stretch=1)

            # Aplicar layout general
            widget.setLayout(main_layout)
            widget.setStyleSheet("""
                QWidget {
                    background-color: #262626;
                    border: 1px solid #3d3d3d;
                    border-radius: 6px;
                }
            """)

            item.setSizeHint(widget.sizeHint())
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, widget)







    #Función para buscar una nota por palabra clave
    def filter_notes(self, keyword):
        filtered = [n for n in self.notes_data if keyword.lower() in n[0].lower() or keyword.lower() in n[2].lower()]
        self.render_notes(filtered)

    #Función para crear notas
    def create_note(self):
        class NoteDialog(QDialog):
            def __init__(self):
                super().__init__()
                self.setWindowTitle("Nueva Nota")
                self.setStyleSheet("background-color: #2b2b2b; color: white;")
                layout = QVBoxLayout(self)

                self.title_input = QLineEdit()
                self.title_input.setPlaceholderText("Título de la nota")
                layout.addWidget(self.title_input)

                self.content_input = QTextEdit()
                self.content_input.setPlaceholderText("Escribe el contenido aquí...")
                layout.addWidget(self.content_input)

                btn_create = QPushButton("Crear Nota")
                btn_create.clicked.connect(self.accept)
                layout.addWidget(btn_create)

        dialog = NoteDialog()
        if dialog.exec_() == QDialog.Accepted:
            title = dialog.title_input.text().strip()
            content = dialog.content_input.toPlainText()

            if not title:
                QMessageBox.warning(self, "Campo requerido", "Debes ingresar un título.")
                return

            file_path = os.path.join(self.notes_dir, f"{title}.txt")
            if os.path.exists(file_path):
                QMessageBox.warning(self, "Ya existe", "Una nota con ese nombre ya existe.")
                return

            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            self.load_notes()
