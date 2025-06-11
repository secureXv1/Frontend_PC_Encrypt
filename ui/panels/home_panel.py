from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel

class HomePanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        label = QLabel("Bienvenido a BETTY - Simulador PGP Educativo")
        label.setStyleSheet("font-size: 20px; font-weight: bold; margin: 20px;")
        layout.addWidget(label)

        layout.addStretch()
