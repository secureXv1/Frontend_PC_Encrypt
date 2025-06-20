from PyQt5.QtWidgets import QWidget, QLabel, QListWidget, QListWidgetItem, QHBoxLayout, QVBoxLayout
from PyQt5.QtGui import QPixmap, QPainter, QColor
from PyQt5.QtCore import Qt, QPropertyAnimation
from PyQt5.QtSvg import QSvgRenderer
import os

def load_colored_svg_icon(path, color="#00BCD4", size=24):
        renderer = QSvgRenderer(path)
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)

        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(pixmap.rect(), QColor(color))
        painter.end()

        return pixmap

class HomePanel(QWidget):
    def __init__(self):
        super().__init__()

        # Layout principal horizontal
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # 🖼️ Panel izquierdo con imagen centrada
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setStyleSheet("background-color: black;")  # opcional
        main_layout.addWidget(self.image_label, 1)

        # 📋 Panel derecho con contenido animado
        self.animaciones = []
        self.entradas = []

        content_layout = QVBoxLayout()
        content_layout.setContentsMargins(40, 40, 40, 40)
        content_layout.setSpacing(20)

        # Lista de mensajes como check list
        mensajes = [
            "Seguridad sin compromisos \nTu información permanece protegida en todo momento",
            "Cifrado de nivel avanzado \nBlindaje total para tus archivos y mensajes",
            "Túneles privados de comunicación \nSolo quienes deben ver, verán",
            "Control total de tus datos \nSin intermediarios. Sin rastreo. Sin sorpresas",
            "Funciona con o sin internet \nTu privacidad no depende de la red",
            "Diseñada para lo crítico \nIdeal para organizaciones y equipos de seguridad",
            "Archivos invisibles para ojos no autorizados \nLo oculto, permanece oculto.",
            "Modo discreto \nInterfaz limpia, sin marcas visibles, sin huellas digitales",
            "Identidad flexible \nUsa distintos alias según el contexto, sin revelar tu origen",
        ]

        icon_paths = [
            "assets/icons/lock2.svg",
            "assets/icons/shield.svg",
            "assets/icons/satellite.svg",
            "assets/icons/terminal.svg",
            "assets/icons/wifi.svg",
            "assets/icons/target.svg",
            "assets/icons/hidden.svg",
            "assets/icons/eye-off.svg",
            "assets/icons/user.svg",
        ]

        for texto, icon_path in zip(mensajes, icon_paths):
            partes = texto.split("\n", 1)
            titulo = partes[0].strip()
            subtitulo = partes[1].strip() if len(partes) > 1 else ""

            html = f"""
                <div>
                    <span style='font-weight:bold;'>{titulo}</span><br>
                    <span style='display:inline-block; margin-left:0px; font-size:13px; font-weight:normal; color:#cccccc; margin-top:6px;'>{subtitulo}</span>
                </div>
            """

            icono_label = QLabel()
            icono_label.setPixmap(load_colored_svg_icon(icon_path, color="#FFF", size=38))
            icono_label.setFixedSize(38, 38)
            icono_label.setAlignment(Qt.AlignTop)

            texto_label = QLabel(html)
            texto_label.setStyleSheet("""
                color: white;
                font-size: 15px;
                padding: 6px;
                background-color: #1f1f1f;
                border-left: 4px solid #00BCD4;
                border-radius: 6px;
            """)
            texto_label.setTextFormat(Qt.RichText)
            texto_label.setWordWrap(True)
            texto_label.setVisible(True)

            fila = QHBoxLayout()
            fila.setContentsMargins(0, 0, 0, 0)
            fila.setSpacing(10)
            fila.addWidget(icono_label)
            fila.addWidget(texto_label)

            contenedor = QWidget()
            contenedor.setLayout(fila)
            content_layout.addWidget(contenedor)

            self.entradas.append(texto_label)

        right_widget = QWidget()
        right_widget.setLayout(content_layout)
        main_layout.addWidget(right_widget, 1)

        self.load_centered_image()

    def load_centered_image(self):
        fondo_path = os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
            "assets", "images", "BluePost.jpg"
        )

        fondo_pixmap = QPixmap(fondo_path)
        if fondo_pixmap.isNull():
            print(f"❌ Imagen no encontrada o inválida: {fondo_path}")
            return

        target_size = self.image_label.size()
        if target_size.width() == 0 or target_size.height() == 0:
            return  # Evita errores si aún no está renderizado

        # Escalar para cubrir el área (como background-size: cover)
        scaled_pixmap = fondo_pixmap.scaled(
            target_size,
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        )

        # Recorte centrado
        x_offset = (scaled_pixmap.width() - target_size.width()) // 2
        y_offset = (scaled_pixmap.height() - target_size.height()) // 2
        cropped_pixmap = scaled_pixmap.copy(
            x_offset, y_offset,
            target_size.width(), target_size.height()
        )

        # Aplicar opacidad
        transparent_pixmap = QPixmap(target_size)
        transparent_pixmap.fill(Qt.transparent)

        painter = QPainter(transparent_pixmap)
        painter.setOpacity(0.9)
        # Calcular posición centrada
        x = (target_size.width() - scaled_pixmap.width()) // 2
        y = (target_size.height() - scaled_pixmap.height()) // 2
        painter.drawPixmap(x, y, scaled_pixmap)
        painter.end()

        self.image_label.setPixmap(transparent_pixmap)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.load_centered_image()

    
   
