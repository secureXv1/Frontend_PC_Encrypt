import socket

HOST = '0.0.0.0'  # Escucha en todas las interfaces
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"🔌 Esperando conexión en el puerto {PORT}...")
    conn, addr = server.accept()
    with conn:
        print(f"📥 Conectado desde {addr}")
        filename = conn.recv(1024).decode().strip()
        with open(filename, "wb") as f:
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                f.write(data)
        print(f"✅ Archivo '{filename}' recibido correctamente.")
