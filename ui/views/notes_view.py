import os
import datetime
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QListWidget, QPushButton,
    QLabel, QLineEdit, QListWidgetItem, QDialog, QTextEdit, QMessageBox
)
from PyQt5.QtGui import QIcon, QCursor
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QFont, QPixmap, QPainter, QColor
from PyQt5.QtWidgets import QSizePolicy, QMenu, QAction
from functools import partial


class NotesView(QWidget):
    def __init__(self, notes_dir="NotasApp"):
        super().__init__()
        self.notes_dir = os.path.join(os.path.expanduser("~"), notes_dir)
        os.makedirs(self.notes_dir, exist_ok=True)

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)
      

        # Contenedor del botón de acción
        icon_buttons_layout = QHBoxLayout()
        icon_buttons_layout.setContentsMargins(0, 10, 0, 10)
        icon_buttons_layout.setSpacing(20)
        icon_buttons_layout.setAlignment(Qt.AlignCenter)

        # Icono para crear nueva nota
        create_note_btn = QPushButton()
        create_note_btn.setIcon(QIcon("assets/icons/create.svg"))
        create_note_btn.setIconSize(QSize(38, 38))
        create_note_btn.setCursor(Qt.PointingHandCursor)
        create_note_btn.setToolTip("Nueva Nota")
        create_note_btn.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
            }
            QPushButton:hover {
                background-color: transparent;
                border-radius: 6px;
            }
        """)
        create_note_btn.clicked.connect(self.create_note)
        icon_buttons_layout.addWidget(create_note_btn)

        # Agregar el contenedor al layout principal
        self.layout.addLayout(icon_buttons_layout)


        # 🔍 Barra de búsqueda
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔍 Buscar nota...")
        self.search_bar.textChanged.connect(self.filter_notes)
        self.layout.addWidget(self.search_bar)

        # 📄 Lista de notas
        self.list_widget = QListWidget()

        #Conectar itemClicked con función para abrir nota en modo edición
        self.list_widget.itemClicked.connect(self.edit_note_from_item)

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
            icon_label.setStyleSheet("margin-bottom: 10px;")  #Incluye espacio entre ícono y texto
            

        # Mensaje de texto
        text_label = QLabel("No hay resultados sobre tu búsqueda. Revisa tu ortografía o intenta buscar algo distinto.")
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

            # 🍔 Botón de menú
            menu_button = QPushButton()
            menu_icon = QIcon("assets/icons/menu_notes.svg")  # asegúrate que el icono exista
            menu_button.setIcon(menu_icon)
            menu_button.setFixedSize(42, 42)
            menu_button.setStyleSheet("""
                QPushButton {
                    background: none;
                    border: none;
                }
                QPushButton:hover {
                    background-color: #3c3c3c;
                    border-radius: 4px;
                }
            """)
            menu_button.clicked.connect(partial(self.show_menu, filename, menu_button))

            # Mostrar menú al hacer clic
            def show_menu():
                from PyQt5.QtWidgets import QMenu
                menu = QMenu()
                eliminar_action = menu.addAction("🗑 Eliminar")
                cifrar_action = menu.addAction("🔐 Cifrar")

                action = menu.exec_(menu_button.mapToGlobal(menu_button.rect().bottomLeft()))

                if action == eliminar_action:
                    self.delete_note(filename)
                elif action == cifrar_action:
                    self.encrypt_note(filename)

            menu_button.clicked.connect(show_menu)
            main_layout.addStretch()
            main_layout.addWidget(menu_button)


    #Función para editar una nota al hacer click
    def edit_note_from_item(self, item):
        index = self.list_widget.row(item)
        if 0 <= index < len(self.notes_data):
            filename, _, _ = self.notes_data[index]
            file_path = os.path.join(self.notes_dir, filename)
            self.open_editor(file_path)


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
    
    #Función para editar notas
    def open_editor(self, file_path):
        class EditDialog(QDialog):
            def __init__(self, title, content):
                super().__init__()
                self.setWindowTitle("Editar Nota")
                self.setStyleSheet("background-color: #2b2b2b; color: white;")
                layout = QVBoxLayout(self)

                self.title_input = QLineEdit(title)
                self.title_input.setPlaceholderText("Título de la nota")
                layout.addWidget(self.title_input)

                self.content_input = QTextEdit(content)
                self.content_input.setPlaceholderText("Contenido de la nota")
                layout.addWidget(self.content_input)

                self.save_button = QPushButton("Guardar Cambios")
                self.save_button.clicked.connect(self.accept)
                layout.addWidget(self.save_button)

        # Leer contenido actual
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        original_title = os.path.basename(file_path).replace(".txt", "")
        dialog = EditDialog(original_title, content)

        if dialog.exec_() == QDialog.Accepted:
            new_title = dialog.title_input.text().strip()
            new_content = dialog.content_input.toPlainText()

            if not new_title:
                QMessageBox.warning(self, "Campo requerido", "Debes ingresar un título.")
                return

            new_path = os.path.join(self.notes_dir, f"{new_title}.txt")

            # Si cambió el título y el archivo nuevo ya existe
            if new_title != original_title and os.path.exists(new_path):
                QMessageBox.warning(self, "Ya existe", "Una nota con ese título ya existe.")
                return

            # Si cambió el nombre, renombrar
            if new_title != original_title:
                os.rename(file_path, new_path)
                file_path = new_path

            # Guardar cambios
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(new_content)

            self.load_notes()
    
    #Función para desplegar menú de opciones en notas
    def show_menu(self, filename, button):
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #2b2b2b;
                color: white;
                border: 1px solid #444;
            }
            QMenu::item:selected {
                background-color: #444444;
            }
        """)

        # Acción eliminar
        delete_action = QAction("🗑 Eliminar", self)
        delete_action.triggered.connect(lambda: self.delete_note(filename))
        menu.addAction(delete_action)

        # Acción cifrar
        encrypt_action = QAction("🔒 Cifrar", self)
        encrypt_action.triggered.connect(lambda: self.encrypt_note(filename))
        menu.addAction(encrypt_action)

        # Mostrar menú junto al botón clicado
        menu.exec_(button.mapToGlobal(button.rect().bottomRight()))
    
    #Función para eliminar nota
    def delete_note(self, filename):
        path = os.path.join(self.notes_dir, filename)
        confirm = QMessageBox.question(
            self,
            "Eliminar Nota",
            f"¿Estás seguro de eliminar la nota '{filename}'?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            try:
                os.remove(path)
                self.load_notes()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo eliminar la nota:\n{str(e)}")

    #Función para cifrar nota
    def encrypt_note(self, filename):
        QMessageBox.information(self, "Cifrar", f"⚙️ Aquí se cifraría la nota: {filename}")
        # Aquí podrías abrir el diálogo de cifrado o redirigir a la lógica existente
    
    
