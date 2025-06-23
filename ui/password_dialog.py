from PyQt5 import QtWidgets, QtGui, QtCore

class PasswordDialog(QtWidgets.QDialog):
    def __init__(self, confirm=True, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Contraseña")
        self.setModal(True)
        self.setFixedWidth(400)
        self.confirm = confirm
        self.password = ""
        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        self.label = QtWidgets.QLabel("Ingresa una contraseña segura:")
        self.label.setStyleSheet("color: white; font-size: 14px;")
        layout.addWidget(self.label)

        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.password_input.textChanged.connect(self.check_strength)
        layout.addWidget(self.password_input)

        if self.confirm:
            self.confirm_label = QtWidgets.QLabel("Confirma tu contraseña:")
            self.confirm_label.setStyleSheet("color: white; font-size: 14px;")
            layout.addWidget(self.confirm_label)

            self.confirm_input = QtWidgets.QLineEdit()
            self.confirm_input.setEchoMode(QtWidgets.QLineEdit.Password)
            layout.addWidget(self.confirm_input)

        self.strength_bar = QtWidgets.QProgressBar()
        self.strength_bar.setMaximum(100)
        self.strength_bar.setTextVisible(True)
        layout.addWidget(self.strength_bar)

        buttons = QtWidgets.QHBoxLayout()
        self.ok_btn = QtWidgets.QPushButton("Aceptar")
        self.ok_btn.clicked.connect(self.accept)
        self.cancel_btn = QtWidgets.QPushButton("Cancelar")
        self.cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(self.ok_btn)
        buttons.addWidget(self.cancel_btn)
        layout.addLayout(buttons)

        self.setStyleSheet("""
            QDialog {
                background-color: #2b2b2b;
            }
            QLineEdit {
                padding: 6px;
                border-radius: 4px;
                background-color: #1e1e1e;
                color: white;
                border: 1px solid #555;
            }
            QProgressBar {
                height: 14px;
                border: 1px solid #666;
                border-radius: 5px;
                background-color: #1e1e1e;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                border-radius: 5px;
            }
            QPushButton {
                background-color: #00BCD4;
                color: white;
                padding: 8px;
                font-weight: bold;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #0097a7;
            }
        """)

    def check_strength(self, text):
        strength = 0
        if len(text) >= 8:
            strength += 30
        if any(c.isdigit() for c in text):
            strength += 20
        if any(c.islower() for c in text) and any(c.isupper() for c in text):
            strength += 30
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in text):
            strength += 20

        self.strength_bar.setValue(min(strength, 100))

        palette = self.strength_bar.palette()
        if strength < 50:
            chunk_color = QtGui.QColor("#e53935")
            label = "Débil"
        elif strength < 80:
            chunk_color = QtGui.QColor("#fbc02d")
            label = "Media"
        else:
            chunk_color = QtGui.QColor("#43a047")
            label = "Fuerte"

        self.strength_bar.setFormat(f"{label} ({strength}%)")
        palette.setColor(QtGui.QPalette.Highlight, chunk_color)
        self.strength_bar.setPalette(palette)

    def accept(self):
        pwd = self.password_input.text()
        if self.confirm:
            confirm_pwd = self.confirm_input.text()
            if pwd != confirm_pwd:
                QtWidgets.QMessageBox.warning(self, "Error", "Las contraseñas no coinciden.")
                return
        self.password = pwd
        super().accept()

    def get_password(self):
        return self.password
