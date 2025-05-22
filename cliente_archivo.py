import socket
import os

HOST = 'IP_DEL_SERVIDOR'  # Reemplazar por la IP de la PC destino
PORT = 65432
ARCHIVO = 'archivo_a_enviar.png'  # O archivo cifrado .json

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(ARCHIVO.encode())  # Primero envía el nombre
    with open(ARCHIVO, "rb") as f:
        s.sendfile(f)
    print("✅ Archivo enviado correctamente.")
