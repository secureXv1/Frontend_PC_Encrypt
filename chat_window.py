from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLineEdit
from password_utils import verificar_password

class ChatWindow(QWidget):
    def __init__(self, alias, socket):
        super().__init__()
        self.alias = alias
        self.socket = socket
        self.setWindowTitle(f"Túnel - {alias}")
        self.resize(400, 300)

        layout = QVBoxLayout()
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Escribe un mensaje...")

        self.input_field.returnPressed.connect(self.enviar_mensaje)

        layout.addWidget(self.chat_area)
        layout.addWidget(self.input_field)
        self.setLayout(layout)

    def mostrar_mensaje(self, mensaje):
        self.chat_area.append(mensaje)

    def enviar_mensaje(self):
        texto = self.input_field.text().strip()
        if texto:
            mensaje = f"{self.alias}: {texto}"
            try:
                self.socket.sendall(mensaje.encode())
                self.mostrar_mensaje(mensaje)
                self.input_field.clear()
            except:
                self.mostrar_mensaje("⚠️ Error al enviar el mensaje")
