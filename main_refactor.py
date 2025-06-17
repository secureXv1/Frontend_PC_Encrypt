from app_logger import logger
import threading

try:
    from PyQt5 import QtWidgets, QtCore  # type: ignore
except Exception as e:  # pragma: no cover - env may lack PyQt5
    QtWidgets = None
    QtCore = None
    logger.error(f"No se pudo importar PyQt5: {e}")
import sys
from registrar_info_red import registrar_info_en_db

main_window = None

if QtWidgets:
    from db_cliente import get_client_uuid, obtener_info_equipo
    from ui.sidebar import Sidebar
    from ui.panels.home_panel import HomePanel
    from ui.panels.tunnel_panel import TunnelPanel
    from ui.panels.encryption_panel import EncryptionPanel
    from ui.panels.settings_panel import SettingsPanel

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
        logger.info("Iniciando interfaz gráfica...")
        try:
            app = QtWidgets.QApplication(sys.argv)
        except Exception as exc:
            logger.error(f"No se pudo iniciar QApplication: {exc}", exc_info=True)
            return

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
        try:
            window = MainWindow(uuid=uuid, hostname=info["hostname"], sistema=info["sistema"])
            window.show()
            global main_window
            main_window = window

            def start_registration():
                logger.info("Iniciando registro de red en segundo plano")

                def worker():
                    try:
                        registrar_info_en_db()
                    except Exception:
                        logger.exception("Error en registro de red")

                try:
                    from multiprocessing import Process
                    Process(target=worker, daemon=True).start()
                except Exception as e:
                    logger.warning(f"Fallo al iniciar proceso para registro: {e}")
                    threading.Thread(target=worker, daemon=True).start()

            if QtCore:
                # Retrasar un poco para dar tiempo a que cargue la interfaz
                QtCore.QTimer.singleShot(1000, start_registration)
            else:
                start_registration()

            logger.info("Aplicación iniciada correctamente")
            sys.exit(app.exec_())
        except Exception as exc:
            logger.error(f"Error ejecutando la interfaz gráfica: {exc}", exc_info=True)
else:
    def main():
        logger.error("PyQt5 no disponible. La interfaz no se puede mostrar.")
        try:
            registrar_info_en_db()
        except Exception:
            logger.exception("No se pudo registrar info en la DB")

if __name__ == "__main__":
    main()
