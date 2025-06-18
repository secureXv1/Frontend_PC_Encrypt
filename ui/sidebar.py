from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QSizePolicy, QSpacerItem, QLabel
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import QSize
from PyQt5.QtGui import QPixmap, QPainter, QColor
from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtCore import Qt

def colored_icon(svg_path, color, size=32):
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

class Sidebar(QWidget):
    def __init__(self, on_select_callback):
        super().__init__()
        self.on_select_callback = on_select_callback
        self.setFixedWidth(80)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 10, 0, 10)
        layout.setSpacing(15)

        title = QLabel("Encrypt")
        title.setStyleSheet("color: white; font-size: 18px; font-weight: bold;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.setStyleSheet("""
            Sidebar QPushButton {
                background-color: transparent;
                color: white;
                border: none;
                padding: 12px;
            }
            Sidebar QPushButton:hover {
                background-color: #2c2c2c; 
            }
            Sidebar QPushButton:checked {
                background-color: #3a3a3a;
                border-left: 4px solid #00BCD4;
            }
            Sidebar QPushButton:checked::icon {
                color: #00BCD4;
            }
        """)

        self.buttons = []
        self.icons = [
            ("assets/icons/home.svg", "Inicio"),
            ("assets/icons/tunnel.svg", "Túneles"),
            ("assets/icons/lock.svg", "Cifrado"),
        ]

        for i, (icon_path, tooltip) in enumerate(self.icons):
            btn = QPushButton()
            btn.setIcon(colored_icon(icon_path, "#FFFFFF"))  # o cualquier color que necesites
            btn.setIconSize(QSize(32, 32))  # Ícono más grande
            btn.setToolTip(tooltip)
            btn.setCheckable(True)
            btn.clicked.connect(lambda _, idx=i: self.select(idx))
            layout.addWidget(btn)
            self.buttons.append(btn)

        layout.addSpacerItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Botón de tema abajo
        self.theme_btn = QPushButton()
        self.theme_btn.setCheckable(True)  
        self.theme_btn.setIcon(colored_icon("assets/icons/settings.svg", "#FFFFFF"))
        self.theme_btn.setIconSize(QSize(28, 28))
        self.theme_btn.setToolTip("Ajustes")
        self.theme_btn.clicked.connect(lambda: self.select(3))  # 👉 activa vista 3 manualmente
        layout.addWidget(self.theme_btn)

        self.select(0)

    def select(self, index):
        for i, btn in enumerate(self.buttons):
            icon_path, _ = self.icons[i]
            color = "#00BCD4" if i == index else "#FFFFFF"
            btn.setIcon(colored_icon(icon_path, color))
            btn.setChecked(i == index)

        # 🔽 Visual para el botón de ajustes (index 3)
        if index == 3:
            # Deselecciona todos los botones superiores
            for btn in self.buttons:
                btn.setChecked(False)
            # Aplica estilo activo al botón de ajustes
            self.theme_btn.setChecked(True)
            self.theme_btn.setIcon(colored_icon("assets/icons/settings.svg", "#00BCD4"))
            self.theme_btn.setStyleSheet("""
                background-color: #3a3a3a;
                border-left: 4px solid #00BCD4;
                padding: 12px;
            """)
        else:
            self.theme_btn.setChecked(False)
            self.theme_btn.setIcon(colored_icon("assets/icons/settings.svg", "#FFFFFF"))
            self.theme_btn.setStyleSheet("""
                background-color: transparent;
                border: none;
                padding: 12px;
            """)

        self.on_select_callback(index)

