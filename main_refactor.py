from app_logger import logger
import threading
from registrar_info_red import registrar_info_en_db
from db_cliente import get_client_uuid, marcar_cliente_desconectado, marcar_cliente_en_linea

def registration_worker():
    """Register network info in a background process/thread."""
    try:
        registrar_info_en_db()
    except Exception:
        logger.exception("Error en registro de red")


def start_registration():
    logger.info("Iniciando registro de red en segundo plano")
    try:
        from multiprocessing import Process
        Process(target=registration_worker, daemon=True).start()
    except Exception as e:  # pragma: no cover - multiprocess may fail on some envs
        logger.warning(f"Fallo al iniciar proceso para registro: {e}")
        threading.Thread(target=registration_worker, daemon=True).start()

try:
    from PyQt5 import QtWidgets, QtCore  # type: ignore
except Exception as e:  # pragma: no cover - env may lack PyQt5
    QtWidgets = None
    QtCore = None
    logger.error(f"No se pudo importar PyQt5: {e}")
import sys

main_window = None

if QtWidgets:
    from db_cliente import get_client_uuid, obtener_info_equipo
    from ui.sidebar import Sidebar
    from ui.panels.home_panel import HomePanel
    from ui.panels.tunnel_panel import TunnelPanel
    from ui.panels.encryption_panel import EncryptionPanel
    from ui.panels.settings_panel import SettingsPanel

    class CustomTitleBar(QtWidgets.QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self.parent = parent
            self.setFixedHeight(35)
            self.setStyleSheet("background-color: #1a1a1a; color: white;")

            layout = QtWidgets.QHBoxLayout(self)
            layout.setContentsMargins(10, 0, 10, 0)

            self.title = QtWidgets.QLabel("Encrypt")
            self.title.setStyleSheet("font-weight: bold; font-size: 22px; color: white;")

            layout.addWidget(self.title)
            layout.addStretch()

            # Botón Minimizar
            self.btn_minimize = QtWidgets.QPushButton("–")
            self.btn_minimize.setFixedSize(30, 30)
            self.btn_minimize.setStyleSheet("""
                QPushButton {
                    background-color: #2a2a2a;
                    border: none;
                    color: white;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #444444;
                }
            """)
            self.btn_minimize.clicked.connect(self.minimize_window)

            # Botón Maximizar
            self.btn_maximize = QtWidgets.QPushButton("□")
            self.btn_maximize.setFixedSize(30, 30)
            self.btn_maximize.setStyleSheet("""
                QPushButton {
                    background-color: #2a2a2a;
                    border: none;
                    color: white;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #444444;
                }
            """)
            self.btn_maximize.clicked.connect(self.maximize_window)

            # Botón Cerrar
            self.btn_close = QtWidgets.QPushButton("✕")
            self.btn_close.setFixedSize(30, 30)
            self.btn_close.setStyleSheet("""
                QPushButton {
                    background-color: #2a2a2a;
                    border: none;
                    color: white;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #ff5555;
                }
            """)
            self.btn_close.clicked.connect(self.close_window)

            # Agregar botones a la barra de título
            layout.addWidget(self.btn_minimize)
            layout.addWidget(self.btn_maximize)
            layout.addWidget(self.btn_close)

        def close_window(self):
            if self.parent:
                self.parent.close()

        def minimize_window(self):
            if self.parent:
                self.parent.showMinimized()

        def maximize_window(self):
            if self.parent.isMaximized():
                self.parent.showNormal()
            else:
                self.parent.showMaximized()

        def mousePressEvent(self, event):
            self.offset = event.globalPos()

        def mouseMoveEvent(self, event):
            if event.buttons() == QtCore.Qt.LeftButton:
                delta = event.globalPos() - self.offset
                self.parent.move(self.parent.pos() + delta)
                self.offset = event.globalPos()


    class MainWindow(QtWidgets.QMainWindow):
        def __init__(self, uuid, hostname, sistema):
            super().__init__()
            self.setGeometry(50, 50, 1200, 800)  # Más pequeño
            self.setWindowTitle("Encrypt")
            self.setWindowFlags(QtCore.Qt.FramelessWindowHint)  # Oculta barra superior del SO

            main_widget = QtWidgets.QWidget()
            main_layout = QtWidgets.QVBoxLayout(main_widget)
            main_layout.setContentsMargins(0, 0, 0, 0)
            main_layout.setSpacing(0)

            # Barra personalizada
            self.title_bar = CustomTitleBar(self)
            main_layout.addWidget(self.title_bar)

            # Contenido principal
            content_widget = QtWidgets.QWidget()
            layout = QtWidgets.QHBoxLayout(content_widget)

            self.pages = QtWidgets.QStackedWidget()
            self.pages.addWidget(HomePanel())           # index 0
            self.pages.addWidget(EncryptionPanel())     # index 1
            self.pages.addWidget(TunnelPanel(uuid=uuid, hostname=hostname, sistema=sistema))  # index 2
            self.pages.addWidget(SettingsPanel())       # index 3

            sidebar = Sidebar(self.cambiar_pagina)
            layout.addWidget(sidebar, 1)
            layout.addWidget(self.pages, 5)

            main_layout.addWidget(content_widget)
            self.setCentralWidget(main_widget)

        def cambiar_pagina(self, index):
            self.pages.setCurrentIndex(index)

        def closeEvent(self, event):
            uuid = get_client_uuid()
            marcar_cliente_desconectado(uuid)
            print(f"🛑 Cliente {uuid} marcado como desconectado.")
            event.accept()


    def main():
        logger.info("Iniciando interfaz gráfica...")
        try:
            app = QtWidgets.QApplication(sys.argv)
        except Exception as exc:
            logger.error(f"No se pudo iniciar QApplication: {exc}", exc_info=True)
            return

        # Datos del cliente
        uuid = get_client_uuid()
        marcar_cliente_en_linea(uuid)
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
            QMainWindow {
                border: 1px solid #303030;
            }
        """)

        # Lanza MainWindow que incluye el sidebar y las páginas
        try:
            window = MainWindow(uuid=uuid, hostname=info["hostname"], sistema=info["sistema"])
            window.show()
            global main_window
            main_window = window

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
