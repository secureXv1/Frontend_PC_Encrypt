# message_bubble.py
from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QHBoxLayout, QSizePolicy
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QPalette, QPixmap, QPainter
from PyQt5.QtSvg import QSvgRenderer
from datetime import datetime

def _colored_pixmap(svg_path, color, size=16):
    renderer = QSvgRenderer(svg_path)
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter)
    painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
    painter.fillRect(pixmap.rect(), QColor(color))
    painter.end()
    return pixmap


class MessageBubble(QWidget):
    def __init__(self, text, sender, is_sender, timestamp=None, url=None, link_handler=None, is_file=False):
        super().__init__()

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(2)

        # Nombre
        if not is_sender:
            name_label = QLabel(sender)
            name_label.setStyleSheet("color: #555; font-weight: bold; font-size: 10px;")
            layout.addWidget(name_label)

        bubble = QWidget()
        bubble_layout = QHBoxLayout(bubble)
        bubble_layout.setContentsMargins(6, 6, 6, 6)
        bubble_layout.setSpacing(4)

        if is_file:
            icon_lbl = QLabel()
            pix = _colored_pixmap("assets/icons/file.svg", "#FFFFFF", 16)
            icon_lbl.setPixmap(pix)
            bubble_layout.addWidget(icon_lbl)

        text_label = QLabel()
        if url:
            text_label.setText(f'<a href="{url}">{text}</a>')
            text_label.setTextFormat(Qt.RichText)
            text_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
            text_label.setOpenExternalLinks(False)
            if link_handler:
                text_label.linkActivated.connect(lambda _: link_handler(url, text))
        else:
            text_label.setText(text)
        text_label.setWordWrap(True)
        bubble_layout.addWidget(text_label)

        bubble.setStyleSheet(
            "color: #FFF; background-color: #00BCD4; border-radius: 8px;"
            if is_sender
            else "color: #FFF; background-color: #444; border-radius: 8px;"
        )
        layout.addWidget(bubble)

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

        self.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
