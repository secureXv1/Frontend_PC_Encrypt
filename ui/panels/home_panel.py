from PyQt5.QtWidgets import QWidget, QLabel, QListWidget, QListWidgetItem, QHBoxLayout, QVBoxLayout
from PyQt5.QtGui import QPixmap, QPainter
from PyQt5.QtCore import Qt, QPropertyAnimation
import os

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

        # 🟦 Título principal
        titulo = QLabel("ENCRYPT")
        titulo.setStyleSheet("""
            font-size: 26px;
            font-weight: bold;
            color: white;
            background-color: rgba(0,0,0,0);
            padding: 6px;
        """)
        titulo.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(titulo)

       # 🟨 Subtítulo limpio sin fondo ni padding extra
        subtitulo = QLabel("La seguridad no es una opción, es una responsabilidad")
        subtitulo.setStyleSheet("""
            font-size: 15px;
            color: #cccccc;
            background: transparent;
        """)
        subtitulo.setAlignment(Qt.AlignCenter)
        content_layout.addWidget(subtitulo)

        # Lista de mensajes como check list
        mensajes = [
            "🔍 Escaneo del entorno completado",
            "✅ Identidad del dispositivo verificada",
            "🔐 Claves de sesión generadas",
            "🛰️ Conexión cifrada establecida",
            "🟢 Chat listo para comunicarse",
        ]

        for i, texto in enumerate(mensajes):
            label = QLabel(texto)
            label.setStyleSheet("""
                color: white;
                font-size: 15px;
                padding: 4px;
                background-color: #1f1f1f;
                border-left: 4px solid #00cc88;
                border-radius: 6px;
            """)
            label.setGraphicsEffect(None)
            label.setVisible(False)
            content_layout.addWidget(label)
            self.entradas.append(label)

        right_widget = QWidget()
        right_widget.setLayout(content_layout)
        main_layout.addWidget(right_widget, 1)

        self.load_centered_image()

        from PyQt5.QtCore import QTimer, QPropertyAnimation

        QTimer.singleShot(500, lambda: [
            QTimer.singleShot(i * 600, lambda l=label: self._mostrar_con_animacion(l))
            for i, label in enumerate(self.entradas)
        ])
    def iniciar_animaciones(self):
        from PyQt5.QtCore import QTimer, QPropertyAnimation
        for i, label in enumerate(self.entradas):
            QTimer.singleShot(i * 600, lambda l=label: self._mostrar_con_animacion(l))

    def _mostrar_con_animacion(self, label):
        label.setVisible(True)
        anim = QPropertyAnimation(label, b"windowOpacity")
        anim.setDuration(700)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.start()
        self.animaciones.append(anim)  # mantener referencia

    def load_centered_image(self):
        fondo_path = os.path.join(
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")),
            "assets", "images", "cyber-security-3400657_1280.jpg"
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
        painter.setOpacity(0.35)
        # Calcular posición centrada
        x = (target_size.width() - scaled_pixmap.width()) // 2
        y = (target_size.height() - scaled_pixmap.height()) // 2
        painter.drawPixmap(x, y, scaled_pixmap)
        painter.end()

        self.image_label.setPixmap(transparent_pixmap)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.load_centered_image()
