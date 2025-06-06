from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import os, json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import threading
from chat_window import ChatWindow
from tunnel_client import TunnelClient
from password_utils import verificar_password
from db_cliente import crear_tunel, obtener_tunel_por_nombre, guardar_uuid_localmente, get_client_uuid, registrar_cliente
import platform, socket, uuid
import requests
import uuid
import socket
import platform

# 📌 Obtener datos del equipo
def obtener_info_equipo():
    return {
        "uuid": str(uuid.getnode()),
        "hostname": socket.gethostname(),
        "sistema": platform.system() + " " + platform.release()
    }

# registro de los equipos
def registrar_en_backend():
    info = obtener_info_equipo()
    try:
        response = requests.post("http://symbolsaps.ddns.net:8000/api/registrar_cliente", json=info)
        response.raise_for_status()
    except Exception as e:
        print("❌ Error al registrar cliente en el backend:", e)

# Llama esto al iniciar
registrar_en_backend()


#Panel de Tuneles - salas de chat
class TunnelPanel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.parent = parent

        layout = QtWidgets.QVBoxLayout()
        self.setLayout(layout)

        # Campos para ingresar nombre, contraseña y alias
        self.input_name = QtWidgets.QLineEdit()
        self.input_name.setPlaceholderText("Nombre del túnel")
        self.input_password = QtWidgets.QLineEdit()
        self.input_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.input_password.setPlaceholderText("Contraseña")
        self.input_alias = QtWidgets.QLineEdit()
        self.input_alias.setPlaceholderText("Tu alias")

        self.layout().addWidget(QtWidgets.QLabel("🛡 Mis Túneles"))
        self.layout().addWidget(self.input_name)
        self.layout().addWidget(self.input_password)
        self.layout().addWidget(self.input_alias)

        self.tunnel_list = QtWidgets.QListWidget()
        self.layout().addWidget(self.tunnel_list)

        btn_layout = QtWidgets.QHBoxLayout()
        self.btn_create = QtWidgets.QPushButton("➕ Crear Túnel")
        self.btn_connect = QtWidgets.QPushButton("🔌 Conectarse")
        btn_layout.addWidget(self.btn_create)
        btn_layout.addWidget(self.btn_connect)
        self.layout().addLayout(btn_layout)

        self.chat_area = QtWidgets.QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_input = QtWidgets.QLineEdit()
        self.chat_input.setPlaceholderText("Escribe un mensaje...")
        self.btn_send = QtWidgets.QPushButton("Enviar")

        chat_input_layout = QtWidgets.QHBoxLayout()
        chat_input_layout.addWidget(self.chat_input)
        chat_input_layout.addWidget(self.btn_send)

        self.layout().addWidget(QtWidgets.QLabel("💬 Chat del Túnel"))
        self.layout().addWidget(self.chat_area)
        self.layout().addLayout(chat_input_layout)

        # Ocultar chat inicialmente
        self.chat_area.hide()
        self.chat_input.hide()
        self.btn_send.hide()

        # Conectar botones
        self.btn_create.clicked.connect(self.parent.crear_tunel_desde_ui)
        self.btn_connect.clicked.connect(self.unirse_a_tunel_desde_ui)
        self.btn_send.clicked.connect(self.enviar_mensaje)

        # Cliente de túnel
        self.cliente = None

    def unirse_a_tunel_desde_ui(self):
        nombre = self.input_name.text().strip()
        password = self.input_password.text().strip()
        alias = self.input_alias.text().strip()

        if not nombre or not password or not alias:
            print("⚠️ Todos los campos son obligatorios.")
            return

        try:
            tunel = obtener_tunel_por_nombre(nombre)
            if not tunel:
                print("❌ Túnel no encontrado.")
                return

            if not verificar_password(password, tunel["password_hash"]):
                print("❌ Contraseña incorrecta.")
                return

            # Crear cliente y conectar
            self.cliente = TunnelClient(
                host="symbolsaps.ddns.net",
                port=5050,
                tunnel_id=tunel["id"],
                alias=alias,
                on_receive_callback=self.recibir_mensaje
            )
            self.cliente.connect()

            # Mostrar área de chat
            self.chat_area.show()
            self.chat_input.show()
            self.btn_send.show()
            self.chat_area.append(f"✅ Conectado al túnel '{nombre}' como {alias}")

        except Exception as e:
            print("❌ No se pudo conectar al túnel:")
            print(e)

    def enviar_mensaje(self):
        mensaje = self.chat_input.text().strip()
        if mensaje and self.cliente:
            try:
                texto = f"{self.input_alias.text()}: {mensaje}"
                self.cliente.socket.sendall(texto.encode())
                self.chat_area.append(f"🧑 Tú: {mensaje}")
                self.chat_input.clear()
            except:
                self.chat_area.append("⚠️ Error al enviar el mensaje")

    def recibir_mensaje(self, mensaje):
        self.chat_area.append(mensaje)


#Panel principal - Cifrado
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("BETTY - Simulador PGP Educativo")
        self.setGeometry(100, 100, 1000, 600)

        #Layout principal
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QtWidgets.QHBoxLayout(central_widget)

        #Panel izquierdo: túneles y chat
        self.left_panel = TunnelPanel(parent=self)

        #Panel derecho: opciones principales
        self.right_panel = QtWidgets.QVBoxLayout()
        self.add_menu_button("🔐 Crear Llaves", self.on_create_keys)
        self.add_menu_button("📦 Cifrar Archivo", self.on_encrypt_file)
        self.add_menu_button("🔓 Descifrar Archivo", self.on_decrypt_file)
        self.add_menu_button("🖼️ Ocultar Archivo Cifrado", self.on_hide_file)
        self.add_menu_button("🔍 Extraer Archivo", self.on_extract_hidden_file)
        self.right_panel.addStretch()

        #Integrar ambos paneles
        main_layout.addWidget(self.left_panel, 3)
        main_layout.addLayout(self.right_panel, 2)
        
    #Función para crear túneles
    def crear_tunel_desde_ui(self):
        import requests
        from password_utils import hash_password

        nombre, ok1 = QtWidgets.QInputDialog.getText(self, "Crear Túnel", "Nombre del túnel:")
        if not ok1 or not nombre.strip():
            return

        clave, ok2 = QtWidgets.QInputDialog.getText(self, "Crear Túnel", "Contraseña:", QtWidgets.QLineEdit.Password)
        if not ok2 or not clave.strip():
            return

        try:
            response = requests.post("http://symbolsaps.ddns.net:8000/api/tunnels/create", json={
                "name": nombre.strip(),
                "password": clave
            })

            if response.status_code == 201:
                tunnel_id = response.json()["tunnel_id"]
                # continúa con UI
            else:
                raise Exception(response.text)

            self.left_panel.tunnel_list.addItem(nombre.strip())
            self.left_panel.chat_area.append(f"🔐 Túnel '{nombre.strip()}' creado exitosamente.")

            # Si tienes lógica para iniciar servidor de túnel, la puedes colocar aquí
            # Por ejemplo:
            # threading.Thread(target=iniciar_servidor_tunel, args=(nombre.strip(), tunnel_id), daemon=True).start()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo crear el túnel:\n{str(e)}")

    #Función para conectarse a un tunel
    from tunnel_client import TunnelClient
    from chat_window import ChatWindow

    def unirse_a_tunel_desde_ui(self):
        try:
            response = requests.get("http://symbolsaps.ddns.net:8000/api/tunnels/get", params={"name": nombre})
            if response.status_code == 200:
                tunel = response.json()
            else:
                raise Exception("Túnel no encontrado")

            from password_utils import verificar_password

            nombre = self.left_panel.input_name.text()
            password = self.left_panel.input_password.text()
            alias = self.left_panel.input_alias.text() or "Anónimo"

            tunel = obtener_tunel_por_nombre(nombre)
            if not tunel:
                QtWidgets.QMessageBox.warning(self, "Error", "Túnel no encontrado")
                return

            if not verificar_password(password, tunel["password_hash"]):
                QtWidgets.QMessageBox.warning(self, "Error", "Contraseña incorrecta")
                return

            tunel_id = tunel["id"]

            # Conectamos al servidor de túnel
            self.cliente = TunnelClient(
                host="symbolsaps.ddns.net",  # cambia por IP real si no es local
                port=5050,
                tunnel_id=tunel_id,
                alias=alias,
                on_receive_callback=self.recibir_mensaje
            )
            self.cliente.connect()

            # Abrir ventana de chat
            self.chat_window = ChatWindow(alias, self.cliente.sock, tunel_id)
            self.chat_window.show()

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo conectar al túnel:\n{e}")

    def add_menu_button(self, label, callback):
        button = QtWidgets.QPushButton(label)
        button.setFixedHeight(40)
        button.clicked.connect(callback)
        self.right_panel.addWidget(button)

    #+++++FUNCIONES PRINCIPALES++++++placeholder+++++
    #Función para crear llaves (pública y privada)
    def on_create_keys(self):
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar clave (nombre base)", "", "PEM Files (*.pem);;All Files (*)", options=options)
        
        if not file_path:
            return  #Cancelado por el usuario
        
        base_name = file_path.rsplit(".", 1)[0]  #Quitar extensión si la hay
        
        #Generar clave privada
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        #Serializar y guardar clave privada
        with open(f"{base_name}_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
            #Serializar y guardar clave pública
            public_key = private_key.public_key()
            with open(f"{base_name}_public.pem", "wb") as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            #Guardar la ruta donde se guardaron las claves (pública y privada)
            #self.public_key_path = f"{base_name}_public.pem"
            self.private_key_path = f"{base_name}_private.pem"
                
            QtWidgets.QMessageBox.information(self, "✅ Éxito",
                f"Claves generadas:\n{base_name}_private.pem\n{base_name}_public.pem")

   
    #Función para cifrar
    def on_encrypt_file(self):
        input_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo a cifrar", "", "All Files (*)")
        
        if not input_file:
            return

        #Seleccionar clave pública
        public_key_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar clave pública (.pem)", "", "Claves Públicas (*.pem);;All Files (*)")
             
             
        if not public_key_file:
            return

    #Seleccionar ruta de salida
        output_file, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo cifrado", "", "Archivo Cifrado (*.json)")

        if not output_file:
            return

        try:
            cifrar_archivo_con_rsa(input_file, public_key_file, output_file)
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo cifrado guardado en:\n{output_file}")
            self.left_panel.chat_area.append("📦 Archivo cifrado exitosamente.")
            # 🛰️ Lanzar servidor del túnel
            puerto = 5050 + tunnel_id  # o usar cualquier otra fórmula
            threading.Thread(target=iniciar_servidor_tunel, args=(tunnel_id, puerto), daemon=True).start()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo cifrar el archivo:\n{e}")



    #Función para descifrar
    def on_decrypt_file(self):

        if not hasattr(self, 'private_key_path'):
            private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "Seleccionar tu clave privada", "", "PEM Files (*.pem);;All Files (*)")
            
            if not private_key_path:
                return
        
        else:
            private_key_path = self.private_key_path
        
        #Seleccionar archivo a descifrar
        encrypted_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "All Files (*)")
        
        if not encrypted_file:
            return
        
        try:
            with open(encrypted_file, "r") as f:
                payload = json.load(f)
                
                encrypted_key = bytes.fromhex(payload["key"])
                encrypted_data = bytes.fromhex(payload["data"])
                #Cargar clave privada
                with open(private_key_path, "rb") as f:
                    priv_key = serialization.load_pem_private_key(f.read(), password=None)

                #Descifrar clave simétrica
                aes_key = priv_key.decrypt(
                    encrypted_key,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

                #Descifrar datos
                fernet = Fernet(aes_key)
                decrypted_serialized = fernet.decrypt(encrypted_data)
                original_payload = json.loads(decrypted_serialized.decode("utf-8"))

                ext = original_payload.get("ext", "")
                if not ext.startswith("."):
                    ext = f".{ext}"

                file_data = base64.b64decode(original_payload["content"])

                #Permitir que el usuario asigne nombre y ruta final
                output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                    self, "Guardar archivo descifrado", f"descifrado{ext}", f"Archivo restaurado (*{ext});;Todos los archivos (*)"
                )
                if not output_path:
                    return
                with open(output_path, "wb") as f:
                    f.write(file_data)

                #Imprimir mensaje de éxito al descifrar
                QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo descifrado guardado como:\n{output_path}")
    
        except Exception as e:
            #Imprimir mensaje de error al descifrar
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo descifrar el archivo:\n{str(e)}")

        
    

    #Función para descifrar archivo extraido
    def descifrar_archivo_extraido(self, file_path):
        
        #Seleccionar clave privada
        priv_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar tu clave privada", "", "PEM Files (*.pem)")
        
        if not priv_key_path:
            QtWidgets.QMessageBox.warning(self, "⚠️ Cancelado", "No se seleccionó una clave privada.")
            return
        
        try:
            with open(file_path, "r") as f:
                payload = json.load(f)
            
            encrypted_key = bytes.fromhex(payload["key"])
            encrypted_data = bytes.fromhex(payload["data"])

            #Cargar clave privada
            with open(priv_key_path, "rb") as f:
                priv_key = serialization.load_pem_private_key(f.read(), password=None)
            
            #Descifrar clave AES
            aes_key = priv_key.decrypt(
                encrypted_key,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            fernet = Fernet(aes_key)
            decrypted_data = fernet.decrypt(encrypted_data)

            #Guardar archivo descifrado
            save_path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Guardar archivo descifrado", "", "All Files (*)")

            if not save_path:
                return
            
            with open(save_path, "wb") as f:
                f.write(decrypted_data)
            
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo descifrado guardado en:\n{save_path}")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo descifrar el archivo:\n{e}")


    #Función para ocultar archivo cifrado en contenedor
    def on_hide_file(self):
        #Seleccionar archivo cifrado (.json)
        cifrado_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "Archivo Cifrado (*.json);;All Files (*)")
        
        if not cifrado_path:
            return
        
        #Seleccionar archivo contenedor (imagen, audio, documento, etc.)
        contenedor_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor", "", "Todos los archivos (*)")
        
        if not contenedor_path:
            return
        
        #Obtener extensión original del archivo contenedor
        cont_ext = os.path.splitext(contenedor_path)[1]

        #Seleccionar dónde guardar el archivo oculto
        destino_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo oculto", f"oculto{cont_ext}", f"Archivo Contenedor (*{cont_ext})")
        
        if not destino_path:
            return
        
        try:
            with open(contenedor_path, "rb") as cont_file:
                cont_data = cont_file.read()
            with open(cifrado_path, "rb") as cif_file:
                 cif_data = cif_file.read()
            
            #Marcar el inicio del contenido oculto con una firma única
            firma = b"<<--BETTY_START-->>"
            oculto = cont_data + firma + cif_data

            with open(destino_path, "wb") as salida:
                salida.write(oculto)
            
            #Imprimir mensaje de éxito al guardar archivo oculto
            QtWidgets.QMessageBox.information(
                self, "✅ Éxito", f"Archivo oculto guardado como:\n{destino_path}"
            )

        except Exception as e:
            #imprimir mensaje de error al guardar archivo oculto
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo ocultar el archivo:\n{e}")


    
    #Función para extraer archivo y descifrar
    def on_extract_hidden_file(self):
        #Seleccionar archivo contenedor
        contenedor_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor", "", "All Files (*)"
        )

        if not contenedor_path:
            return
        
        #Leer contenido del contenedor y buscar delimitador
        try:
            with open(contenedor_path, "rb") as f:
                contenido = f.read()
            
            delimiter = b"<<--BETTY_START-->>"
            idx = contenido.find(delimiter)
            if idx == -1:
                raise Exception("El contenedor está vacío, no se encontró ningún archivo.")
            
            cifrado_data = contenido[idx + len(delimiter):]

            #Intentar obtener la extensión desde el archivo cifrado (sin descifrar)
            try:
                json_payload = json.loads(cifrado_data.decode())
                ext = json_payload.get("ext", "")
                if ext and not ext.startswith("."):
                    ext = f".{ext}"
            except:
                ext = ".json"
            
                      
            #Proponer un nombre de archivo con la extensión detectada
            output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self,
            "Guardar archivo extraído",
            f"extraido{ext}",
            f"Archivo Cifrado (*{ext});;Todos los archivos (*)"
            )
            
            if not output_path:
                return
            
            with open(output_path, "wb") as out:
                out.write(cifrado_data)
            
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo extraído y guardado en:\n{output_path}")
            
            '''
            #Preguntar si desea descifrarlo ahora
            reply = QtWidgets.QMessageBox.question(
                self, "¿Descifrar ahora?",
                "¿Desea descifrar el archivo extraído?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )
            
            if reply == QtWidgets.QMessageBox.Yes:
                self.descifrar_archivo_extraido(output_path)
            '''

        #Imprimir mensaje de error al extraer archivo        
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo extraer el archivo:\n{e}")

            
          
#****FUNCIONES AUXILIARES*****INICIO******

#Función para cifrar un archivo con RSA
def cifrar_archivo_con_rsa(input_path, public_key_path, output_path):
    #Leer datos del archivo a cifrar
    with open(input_path, "rb") as f:
        file_data = f.read()
    
    #Obtener extensión del archivo original
    _, ext = os.path.splitext(input_path)

    #Crear payload original (con extensión + contenido en base64)
    original_payload = {
        "ext": ext,
        "content": base64.b64encode(file_data).decode("utf-8")
    }

    #Convertir el payload original a bytes y cifrar con clave simétrica (AES/Fernet)
    serialized_data = json.dumps(original_payload).encode("utf-8")
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(serialized_data)

    #Cargar clave pública RSA
    with open(public_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    
    #Cifrar la clave AES con RSA
    encrypted_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    #Preparar payload final para guardar
    payload = {
        "key": encrypted_key.hex(),
        "data": encrypted_data.hex()
    }

    #Guardar como archivo JSON
    with open(output_path, "w") as out:
        json.dump(payload, out)




#Función para descifrar un archivo con RSA
def descifrar_archivo_con_rsa(input_path, private_key_path, output_path):
    with open(input_path, "r") as f:
        payload = json.load(f)
        
    encrypted_key = bytes.fromhex(payload["key"])
    encrypted_data = bytes.fromhex(payload["data"])

    #Cargar clave privada
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    #Descifrar clave AES
    aes_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    #Descifrar contenido cifrado
    fernet = Fernet(aes_key)
    decrypted_serialized = fernet.decrypt(encrypted_data)

    #Decodificar el contenido interno
    original_payload = json.loads(decrypted_serialized)
    extension = original_payload.get("ext", "")
    content_base64 = original_payload.get("content", "")

    #Restaurar contenido original
    file_data = base64.b64decode(content_base64)

    #Restaurar extensión si no está incluida
    if extension and not output_path.endswith(extension):
        output_path += extension

    #Guardar archivo restaurado
    with open(output_path, "wb") as f:
        f.write(file_data)


#Función para ocultar archivo cifrado en un contenedor
def ocultar_archivo_en_contenedor(contenedor_path, archivo_oculto_path, salida_path):
    with open(contenedor_path, "rb") as contenedor:
        contenedor_data = contenedor.read()

    with open(archivo_oculto_path, "rb") as archivo_oculto:
        datos_ocultos = archivo_oculto.read()

    #Añade una firma
    firma = b"<<--BETTY_START-->>"

    with open(salida_path, "wb") as salida:
        salida.write(contenedor_data)
        salida.write(firma)
        salida.write(datos_ocultos) 

#Función para descifrar archivo extraido
def descifrar_archivo_extraido(self, encrypted_path):
    #Seleccionar la clave privada para descifrar
    private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
        self, "Seleccionar clave privada (.pem)", "", "PEM Files (*.pem)"
    )
    
    if not private_key_path:
        return

    try:
        #Leer archivo cifrado
        with open(encrypted_path, "r") as f:
            payload = json.load(f)

        encrypted_key = bytes.fromhex(payload["key"])
        encrypted_data = bytes.fromhex(payload["data"])

        #Cargar clave privada
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)

        #Descifrar clave AES
        aes_key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

        #Descifrar datos
        fernet = Fernet(aes_key)
        decrypted_serialized = fernet.decrypt(encrypted_data)
        original_payload = json.loads(decrypted_serialized.decode("utf-8"))

        ext = original_payload.get("ext", "")
        if not ext.startswith("."):
            ext = f".{ext}"

        file_data = base64.b64decode(original_payload["content"])

        #Permitir al usuario asignar nombre y ruta del archivo descifrado
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado", f"restaurado{ext}", f"Archivo restaurado (*{ext});;Todos los archivos (*)"
        )

        if not save_path:
            return

        with open(save_path, "wb") as out:
            out.write(file_data)

        #imprimir mensaje de éxito al descifrar
        QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo descifrado guardado en:\n{save_path}")

    except Exception as e:
        #imprimir mensaje de error al descifrar
        QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo descifrar el archivo:\n{str(e)}")

#****FUNCIONES AUXILIARES*****FIN******


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()