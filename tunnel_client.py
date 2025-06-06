import socket
import threading
from password_utils import verificar_password
from db_cliente import crear_tunel, obtener_tunel_por_nombre, guardar_uuid_localmente, get_client_uuid
import requests
import json


class TunnelClient:
    def __init__(self, host, port, tunnel_id, alias, on_receive_callback):
        self.host = host
        self.port = port
        self.tunnel_id = tunnel_id
        self.alias = alias
        self.on_receive_callback = on_receive_callback
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.running = False

    def connect(self):
        self.socket.connect((self.host, self.port))
        
        from main import obtener_info_equipo
        info = obtener_info_equipo()

        # 🔐 Handshake completo
        handshake = {
            "tunnel_id": self.tunnel_id,
            "alias": self.alias,
            "uuid": info["uuid"],
            "hostname": info["hostname"],
            "sistema": info["sistema"]
        }

        # Registrar alias por API
        try:
            requests.post("http://symbolsaps.ddns.net:8000/api/registrar_alias", json={
                "uuid": info["uuid"],
                "tunnel_id": self.tunnel_id,
                "alias": self.alias
            })
        except Exception as e:
            print("⚠️ No se pudo registrar alias:", e)

        # Enviar handshake por socket
        self.socket.sendall((json.dumps(handshake) + "\n").encode("utf-8"))
        self.running = True
        threading.Thread(target=self.receive_loop, daemon=True).start()

    def receive_loop(self):
        try:
            while self.running:
                data = self.socket.recv(4096)
                if not data:
                    break
                mensaje = data.decode()
                self.on_receive_callback(mensaje)
        except Exception as e:
            print(f"Error en receive_loop: {e}")
        finally:
            self.socket.close()
            self.running = False

    def send(self, message):
        self.socket.sendall(message.encode())

    def on_receive_callback(self, data):
        registrar_mensaje(self.tunnel_id, info["uuid"], self.alias, data.decode("utf-8"), tipo="texto")


    def disconnect(self):
        self.running = False
        self.socket.close()
