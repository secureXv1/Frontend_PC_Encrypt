from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QSizePolicy, QSpacerItem

class Sidebar(QWidget):
    def __init__(self, on_select_callback):
        super().__init__()
        self.on_select_callback = on_select_callback

        self.setFixedWidth(60)  # menú más delgado

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.setStyleSheet("""
            background-color: #1a1a1a;
            QPushButton {
                background-color: transparent;
                color: white;
                font-size: 20px;
                border: none;
                padding: 10px 0;
            }
            QPushButton:hover {
                background-color: #2c2c2c;
            }
            QPushButton:checked {
                background-color: #3a3a3a;
                border-left: 4px solid #00BCD4;
            }
        """)

        self.buttons = []
        icons = ["🏠", "🌐", "🔐", "⚙️"]
        tooltips = ["Inicio", "Túneles", "Cifrado", "Ajustes"]

        for i, (icon, tip) in enumerate(zip(icons, tooltips)):
            btn = QPushButton(icon)
            btn.setToolTip(tip)
            btn.setCheckable(True)
            btn.clicked.connect(lambda _, idx=i: self.select(idx))
            layout.addWidget(btn)
            self.buttons.append(btn)

        layout.addSpacerItem(QSpacerItem(0, 0, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Botón inferior para tema
        theme_btn = QPushButton("🌙")
        theme_btn.setToolTip("Cambiar tema")
        layout.addWidget(theme_btn)

        self.select(0)  # activar por defecto la primera opción

    def select(self, index):
        for i, btn in enumerate(self.buttons):
            btn.setChecked(i == index)
        self.on_select_callback(index)
