import socket
import threading
from password_utils import verificar_password

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
        handshake = {
            "tunnel_id": self.tunnel_id,
            "alias": self.alias
        }
        self.socket.sendall((str(handshake).replace("'", '"')).encode())
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

    def disconnect(self):
        self.running = False
        self.socket.close()
