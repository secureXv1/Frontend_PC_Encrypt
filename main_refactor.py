from PyQt5 import QtWidgets
from db_cliente import get_client_uuid, obtener_info_equipo
import sys
from ui.sidebar import Sidebar
from ui.panels.home_panel import HomePanel
from ui.panels.tunnel_panel import TunnelPanel
from ui.panels.encryption_panel import EncryptionPanel
from ui.panels.settings_panel import SettingsPanel
from registrar_info_red import registrar_info_en_db

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, uuid, hostname, sistema):
        super().__init__()
        self.resize(1600, 1000)
        self.setWindowTitle("Encrypt")
        self.setGeometry(100, 100, 1100, 650)

        main_widget = QtWidgets.QWidget()
        self.setCentralWidget(main_widget)
        layout = QtWidgets.QHBoxLayout(main_widget)

        # Crear páginas
        self.pages = QtWidgets.QStackedWidget()
        self.pages.addWidget(HomePanel())  # index 0
        self.pages.addWidget(TunnelPanel(uuid=uuid, hostname=hostname, sistema=sistema))  # index 1
        self.pages.addWidget(EncryptionPanel())  # index 2
        self.pages.addWidget(SettingsPanel())  # index 3

        sidebar = Sidebar(self.cambiar_pagina)
        layout.addWidget(sidebar, 1)
        layout.addWidget(self.pages, 5)

    def cambiar_pagina(self, index):
        self.pages.setCurrentIndex(index)
        
def main():
    app = QtWidgets.QApplication(sys.argv)

    # Datos del cliente
    uuid = get_client_uuid()
    info = obtener_info_equipo()

    # Estilos
    app.setStyleSheet("""
        QWidget {
            background-color: #121212;
            color: #e0e0e0;
            font-family: 'Segoe UI', sans-serif;
            font-size: 13px;
        }
        QPushButton {
            background-color: #333;
            color: white;
            border-radius: 6px;
            padding: 6px 12px;
        }
        QPushButton:hover {
            background-color: #444;
        }
        QLineEdit, QTextEdit {
            background-color: #1e1e1e;
            color: white;
            border: 1px solid #2c2c2c;
            border-radius: 4px;
            padding: 6px;
        }
        QScrollArea {
            background-color: #1a1a1a;
        }
        QLabel {
            font-weight: bold;
            color: #b0b0b0;
        }
        QFrame {
            background-color: #1f1f1f;
            border-radius: 10px;
        }
    """)

    # Lanza MainWindow que incluye el sidebar y las páginas
    window = MainWindow(uuid=uuid, hostname=info["hostname"], sistema=info["sistema"])
    window.show()
    sys.exit(app.exec_())

registrar_info_en_db()

if __name__ == "__main__":
    main()
