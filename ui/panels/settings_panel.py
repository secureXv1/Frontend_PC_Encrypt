# ui/panels/settings_panel.py
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox

class SettingsPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)

        title = QLabel("⚙️ Ajustes de la Aplicación")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px;")
        layout.addWidget(title)

        btn_about = QPushButton("ℹ️ Acerca de")
        btn_about.clicked.connect(self.mostrar_info)
        layout.addWidget(btn_about)

        btn_theme = QPushButton("🎨 Cambiar Tema (Próximamente)")
        layout.addWidget(btn_theme)

        layout.addStretch()

    def mostrar_info(self):
        QMessageBox.information(self, "Acerca de", "BETTY - Simulador PGP Educativo\nVersión 1.0\nDesarrollado por tu equipo")
