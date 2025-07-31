from PyQt5.QtSvg import QSvgRenderer
from PyQt5.QtGui import QPixmap, QPainter, QColor, QMovie
from PyQt5.QtCore import Qt, QByteArray, QSize
from PyQt5.QtWidgets import QWidget, QLabel, QHBoxLayout, QVBoxLayout

import os
import re

def load_colored_svg_icon(path, color="#00BCD4", size=38):
    # print(f"🔄 Cargando SVG: {path}")
    if not os.path.exists(path):
        print(f"❌ SVG no encontrado: {path}")
        return QPixmap(size, size)

    try:
        with open(path, 'r', encoding='utf-8') as f:
            svg_data = f.read()

        # 🔁 Forzar color: reemplaza todos los fill existentes
        svg_data = re.sub(r'fill="[^"]+"', f'fill="{color}"', svg_data)

        # Si no tiene fill, añade uno al path principal
        if 'fill=' not in svg_data:
            svg_data = svg_data.replace('<path', f'<path fill="{color}"')

        # 🔧 Reemplazo para stroke si es lo único que existe
        svg_data = re.sub(r'stroke="[^"]+"', f'stroke="{color}"', svg_data)

        renderer = QSvgRenderer(QByteArray(svg_data.encode('utf-8')))
        if not renderer.isValid():
            print(f"⚠️ SVG inválido tras modificar: {path}")
            return QPixmap(size, size)

        image = QPixmap(size, size)
        image.fill(Qt.transparent)

        painter = QPainter(image)
        renderer.render(painter)
        painter.end()

        return image

    except Exception as e:
        print(f"❌ Error al renderizar SVG {path}: {e}")
        return QPixmap(size, size)


class HomePanel(QWidget):
    def __init__(self):
        super().__init__()
        self.background_path = os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
            "assets", "images", "BluePost2.jpg"
        )
        self.background_pixmap = QPixmap(self.background_path)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(40)

        # 🌀 Contenedor vertical: GIF + texto
        texto_con_gif_layout = QVBoxLayout()
        texto_con_gif_layout.setAlignment(Qt.AlignTop)

        # 🎞️ GIF animado (sin fondo)
        gif_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "assets", "images", "welcome.gif"))
        gif_label = QLabel()
        movie = QMovie(gif_path)
        movie.setScaledSize(QSize(180, 180))
        gif_label.setMovie(movie)
        gif_label.setAttribute(Qt.WA_TranslucentBackground)
        gif_label.setStyleSheet("background-color: transparent;")
        gif_label.setAlignment(Qt.AlignHCenter)
        gif_label.setContentsMargins(0, 0, 0, 0)
        movie.start()

        texto_con_gif_layout.addWidget(gif_label)

        # 📝 Texto descriptivo
        texto_label = QLabel()
        texto_label.setText("""
            <div style='color: #00BCD4; font-size: 50px; font-weight: bold;'>
                Encrypt
            </div>
            <div style='color: white; font-size: 25px; font-weight: bold;'>
                Comunicación y Cifrado Seguro, Todo en Uno
            </div>          
            <div style='color: #cccccc; font-size: 15px; margin-top: 12px;'>
                Diseñada para proteger lo que más importa, combina cifrado robusto, anonimato real y 
                control total sobre tus datos. Desde archivos sensibles hasta conversaciones críticas, todo permanece blindado.
            </div>
        """)
        texto_label.setTextFormat(Qt.RichText)
        texto_label.setWordWrap(True)
        texto_label.setAlignment(Qt.AlignTop)
        texto_label.setStyleSheet("background-color: transparent; padding: 20px; border-radius: 10px;")

        texto_con_gif_layout.addWidget(texto_label)

        # 🧱 Contenedor transparente
        texto_container = QWidget()
        texto_container.setLayout(texto_con_gif_layout)
        texto_container.setStyleSheet("background-color: transparent;")

        main_layout.addWidget(texto_container, 2)

        # 📋 Panel derecho con ítems
        content_layout = QVBoxLayout()
        content_layout.setSpacing(20)

        mensajes = [
            "Seguridad sin compromisos \nTu información protegida en todo momento",
            "Cifrado de nivel avanzado \nBlindaje total para tus archivos y mensajes",
            "Túneles privados de comunicación \nSolo quienes deben ver, verán",
            "Control total de tus datos \nSin intermediarios. Sin rastreo. Sin sorpresas",
            "Funciona con o sin internet \nTu privacidad no depende de la red",
            "Diseñada para lo crítico \nIdeal para organizaciones y equipos de seguridad",
            "Archivos invisibles para ojos no autorizados \nLo oculto, permanece oculto.",
            "Modo discreto \nInterfaz limpia, sin marcas, sin huellas digitales",
            "Identidad flexible \nUsa distintos alias sin revelar tu origen",
        ]

        icon_base = os.path.join(os.path.dirname(__file__), "..", "..", "assets", "icons")
        icon_paths = [
            os.path.join(icon_base, "lock2.svg"),
            os.path.join(icon_base, "shield.svg"),
            os.path.join(icon_base, "satellite.svg"),
            os.path.join(icon_base, "terminal.svg"),
            os.path.join(icon_base, "wifi.svg"),
            os.path.join(icon_base, "target.svg"),
            os.path.join(icon_base, "hidden2.svg"),
            os.path.join(icon_base, "eye-off.svg"),
            os.path.join(icon_base, "user.svg"),
        ]


        for texto, icon_path in zip(mensajes, icon_paths):
            partes = texto.split("\n", 1)
            titulo = partes[0].strip()
            subtitulo = partes[1].strip() if len(partes) > 1 else ""

            html = f"""
                <div>
                    <span style='font-weight:bold;'>{titulo}</span><br>
                    <span style='display:inline-block; margin-left:0px; font-size:13px; font-weight:normal; color:white; margin-top:6px;'>{subtitulo}</span>
                </div>
            """

            icono_label = QLabel()
            icono_label.setPixmap(load_colored_svg_icon(icon_path, color="#FF0000", size=38))
            icono_label.setFixedSize(38, 38)
            icono_label.setScaledContents(True)  # 🔹 Asegura que el pixmap se escale al QLabel


            texto_label = QLabel(html)
            texto_label.setStyleSheet("""
                color: white;
                font-size: 15px;
                padding: 6px;
                background-color: rgba(0,0,0,0.3);
                border-left: 4px solid #00BCD4;
                border-radius: 6px;
            """)
            texto_label.setTextFormat(Qt.RichText)
            texto_label.setWordWrap(True)

            fila = QHBoxLayout()
            fila.setContentsMargins(0, 0, 0, 0)
            fila.setSpacing(10)
            fila.addWidget(icono_label)
            fila.addWidget(texto_label)

            contenedor = QWidget()
            contenedor.setLayout(fila)
            content_layout.addWidget(contenedor)

        # Contenedor con fondo transparente para los ítems
        right_container = QWidget()
        right_container.setLayout(content_layout)
        right_container.setStyleSheet("""
            background-color: rgba(0, 0, 0, 0);
            border-radius: 12px;
            padding: 20px;
        """)

        main_layout.addWidget(right_container, 3)


    def paintEvent(self, event):
        super().paintEvent(event)  # ✅ Importante: asegura que los hijos se dibujen
        if not self.background_pixmap.isNull():
            painter = QPainter(self)
            scaled = self.background_pixmap.scaled(
                self.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation
            )
            painter.drawPixmap(0, 0, scaled)
