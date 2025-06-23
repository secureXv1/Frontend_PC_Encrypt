
from PyQt5.QtWidgets import QDialog, QLabel, QVBoxLayout, QComboBox, QPushButton, QHBoxLayout
from PyQt5.QtCore import Qt

class EncryptionMethodDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Método de cifrado")
        self.setFixedWidth(400)
        self.setStyleSheet("background-color: #2b2b2b; color: white; font-size: 14px;")

        layout = QVBoxLayout(self)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)

        label = QLabel("¿Qué método de cifrado deseas utilizar?")
        label.setStyleSheet("font-weight: bold;")
        layout.addWidget(label)

        self.combo = QComboBox()
        self.combo.addItems(["Seleccione una opción...", "Llave de seguridad", "Contraseña"])
        self.combo.setStyleSheet("padding: 6px; background-color: #3c3c3c; color: white;")
        layout.addWidget(self.combo)

        # Botones
        btn_layout = QHBoxLayout()
        self.ok_btn = QPushButton("Aceptar")
        self.ok_btn.clicked.connect(self.accept)
        self.ok_btn.setStyleSheet("background-color: #00BCD4; color: white; padding: 8px 16px; border-radius: 5px;")

        cancel_btn = QPushButton("Cancelar")
        cancel_btn.clicked.connect(self.reject)
        cancel_btn.setStyleSheet("background-color: #555; color: white; padding: 8px 16px; border-radius: 5px;")

        btn_layout.addWidget(self.ok_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)

    def selected_method(self):
        return self.combo.currentText()
