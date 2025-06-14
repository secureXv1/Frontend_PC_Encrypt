# message_bubble.py
from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QSizePolicy
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPalette
from datetime import datetime

class MessageBubble(QWidget):
    def __init__(self, text, sender, is_sender, timestamp=None):
        super().__init__()

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(2)

        # Nombre
        if not is_sender:
            name_label = QLabel(sender)
            name_label.setStyleSheet("color: #555; font-weight: bold; font-size: 10px;")
            layout.addWidget(name_label)

        # Texto
        text_label = QLabel(text)
        text_label.setWordWrap(True)
        text_label.setStyleSheet("""
            padding: 6px;
            background-color: #00BCD4;
            border-radius: 8px;
        """ if is_sender else """
            padding: 6px;
            background-color: #FFF;
            border-radius: 8px;
        """)
        layout.addWidget(text_label)

        # Hora
        if timestamp:
            hora = datetime.fromtimestamp(timestamp / 1000).strftime('%H:%M')
            time_label = QLabel(hora)
            time_label.setStyleSheet("color: #999; font-size: 9px;")
            time_label.setAlignment(Qt.AlignRight)
            layout.addWidget(time_label)

        self.setLayout(layout)

        # Alineación
        if is_sender:
            layout.setAlignment(Qt.AlignRight)
        else:
            layout.setAlignment(Qt.AlignLeft)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
