from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import os, json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#Clave maestra
MASTER_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwF4EDZIm66+kJZlTTiV
TtxAxr60j2CmxLfLBfdvuJdKadmV4i6yatfRSeS+ZGCAFBKwb+jHNNWv2VyWDyGO
3vWqBA4OI69jCFF1R9cOJY4bzDmxB1pB9KgfVX3HtvyMe3Zu8q7+6s6IcthHmaoK
xcXLKTjcsQlVb7hcWMVYaaSwyiPxtRnF/Tk42ys0eps66rM9EKi+K6/mnSzjhquS
XlGY+O2HxGq+H3K8kP8R6iLU09mm5Q11PBoir12wiHQ8m8NiTKzCLAOAt2CCBpyu
UIu1Bie1A04MPaKuvKXpnML5Ib9LGiXcjI6kvjOXhrj1dT8ES8JALGJWnohYZjkJ
0wIDAQAB
-----END PUBLIC KEY-----"""

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#Panel de Tuneles - salas de chat
class TunnelPanel(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QtWidgets.QVBoxLayout())

        #Lista de túneles
        self.tunnel_list = QtWidgets.QListWidget()
        self.layout().addWidget(QtWidgets.QLabel("🛡 Mis Túneles"))
        self.layout().addWidget(self.tunnel_list)

        #Botones para crear/conectarse
        btn_layout = QtWidgets.QHBoxLayout()
        self.btn_create = QtWidgets.QPushButton("➕ Crear Túnel")
        self.btn_connect = QtWidgets.QPushButton("🔌 Conectarse")
        btn_layout.addWidget(self.btn_create)
        btn_layout.addWidget(self.btn_connect)
        self.layout().addLayout(btn_layout)

        #Área de chat
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

        #Ocultar chat inicialmente
        self.chat_area.hide()
        self.chat_input.hide()
        self.btn_send.hide()

        #Conectar acciones
        self.btn_create.clicked.connect(self.crear_tunel)
        self.btn_connect.clicked.connect(self.conectarse_tunel)
        self.btn_send.clicked.connect(self.enviar_mensaje)
    
    #Función para crear túneles
    def crear_tunel(self):
        nombre, ok = QtWidgets.QInputDialog.getText(self, "Crear Túnel", "Nombre del túnel:")
        if ok and nombre.strip():
            self.tunnel_list.addItem(nombre.strip())
            self.chat_area.append(f"🔐 Túnel '{nombre.strip()}' creado.")

    #Función para conectarse a un tunel
    def conectarse_tunel(self):
        item = self.tunnel_list.currentItem()
        if item:
            tunel = item.text()
            self.chat_area.show()
            self.chat_input.show()
            self.btn_send.show()
            self.chat_area.append(f"Te has conectado al túnel '{tunel}'.")

    #Función para enviar mensaje en un tunel - sala de chat
    def enviar_mensaje(self):
        mensaje = self.chat_input.text().strip()
        if mensaje:
            self.chat_area.append(f"🧑 Tú: {mensaje}")
            self.chat_input.clear()

#++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
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
        self.left_panel = TunnelPanel()

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
                
            QtWidgets.QMessageBox.information(self, "Éxito",
                f"Claves generadas:\n{base_name}_private.pem\n{base_name}_public.pem")

   
    #Función para cifrar
    def on_encrypt_file(self):
        # Seleccionar archivo a cifrar
        input_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo a cifrar", "", "Todos los archivos (*)")
        
        if not input_file:
            return

        #Seleccionar clave pública del destinatario
        public_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar clave pública del destinatario", "", "PEM Files (*.pem);;Todos los archivos (*)")
        
        if not public_key_path:
            return

        # Seleccionar ubicación para guardar archivo cifrado
        output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo cifrado", "archivo_cifrado.json", "JSON Files (*.json);;Todos los archivos (*)")
        
        if not output_path:
            return

        try:
            cifrar_archivo_con_rsa(input_file, public_key_path, output_path)
            #Imprimir mensaje de éxito al cifrar
            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo cifrado guardado en:\n{output_path}")
            
        except Exception as e:
            #Imprimir mensaje de error al cifrar
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo cifrar el archivo:\n{str(e)}")



    #Función para descifrar
    def on_decrypt_file(self):
        private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar tu clave privada (.pem)", "", "PEM Files (*.pem);;All Files (*)"
        )
        if not private_key_path:
            return

        encrypted_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado", "", "Archivos cifrados (*.json);;Todos los archivos (*)"
        )
        if not encrypted_file:
            return

        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado como", "descifrado", "Todos los archivos (*)"
        )
        if not save_path:
            return

        try:
            with open(encrypted_file, "r") as f:
                payload = json.load(f)

            encrypted_data = bytes.fromhex(payload["data"])
            encrypted_key_user = bytes.fromhex(payload["key_user"])
            encrypted_key_master = bytes.fromhex(payload["key_master"])

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            try:
                # Intentar con clave del usuario
                aes_key = private_key.decrypt(
                    encrypted_key_user,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            except Exception:
                # Intentar con clave maestra
                aes_key = private_key.decrypt(
                    encrypted_key_master,
                    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

            fernet = Fernet(aes_key)
            decrypted_serialized = fernet.decrypt(encrypted_data)
            original_payload = json.loads(decrypted_serialized.decode("utf-8"))

            ext = original_payload.get("ext", payload.get("ext", ""))  # Recuperar extensión
            file_data = base64.b64decode(original_payload["content"])

            if not save_path.endswith(ext):
                save_path += ext

            with open(save_path, "wb") as f:
                f.write(file_data)

            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado como:\n{save_path}")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo descifrar el archivo:\n{str(e)}")



        
    

    #Función para descifrar archivo extraido
    def descifrar_archivo_extraido(self, encrypted_path):
        private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar clave privada (.pem)", "", "PEM Files (*.pem);;Todos los archivos (*)"
        )
        if not private_key_path:
            return

        try:
            with open(encrypted_path, "r") as f:
                payload = json.load(f)

            encrypted_data = bytes.fromhex(payload["data"])
            encrypted_key_user = bytes.fromhex(payload["key_user"])
            encrypted_key_master = bytes.fromhex(payload["key_master"])

            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)

            try:
                aes_key = private_key.decrypt(
                    encrypted_key_user,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
            except Exception:
                aes_key = private_key.decrypt(
                    encrypted_key_master,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )

            fernet = Fernet(aes_key)
            decrypted_serialized = fernet.decrypt(encrypted_data)
            original_payload = json.loads(decrypted_serialized.decode("utf-8"))

            ext = original_payload.get("ext", "")
            file_data = base64.b64decode(original_payload["content"])

            save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Guardar archivo descifrado como", f"restaurado{ext}", "Todos los archivos (*)"
            )
            if not save_path:
                return

            with open(save_path, "wb") as out:
                out.write(file_data)

            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo descifrado guardado en:\n{save_path}")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo descifrar el archivo:\n{str(e)}")





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
                self, "Éxito", f"Archivo oculto guardado como:\n{destino_path}"
            )

        except Exception as e:
            #imprimir mensaje de error al guardar archivo oculto
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo ocultar el archivo:\n{e}")


    
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
            
            QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo extraído y guardado en:\n{output_path}")
            
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
            QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo extraer el archivo:\n{e}")


         
#+++++FUNCIONES AUXILIARES+++++INICIO+++++

#Función para cifrar un archivo con RSA
def cifrar_archivo_con_rsa(input_path, public_key_path, output_path):
    # Leer datos del archivo a cifrar
    with open(input_path, "rb") as f:
        file_data = f.read()

    # Preparar estructura JSON con contenido y extensión
    _, ext = os.path.splitext(input_path)
    original_payload = {
        "ext": ext,
        "content": base64.b64encode(file_data).decode("utf-8")
    }
    serialized_data = json.dumps(original_payload).encode("utf-8")

    # Generar clave AES y cifrar datos
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(serialized_data)

    # Cargar clave pública del usuario
    with open(public_key_path, "rb") as f:
        pub_user = serialization.load_pem_public_key(f.read())

    # Cargar clave pública maestra desde cadena embebida
    pub_master = serialization.load_pem_public_key(MASTER_PUBLIC_KEY_PEM)

    # Cifrar la clave AES con ambas claves públicas
    encrypted_key_user = pub_user.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_key_master = pub_master.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Guardar archivo cifrado incluyendo extensión
    payload = {
        "key_user": encrypted_key_user.hex(),
        "key_master": encrypted_key_master.hex(),
        "data": encrypted_data.hex(),
        "ext": ext
    }

    with open(output_path, "w") as out:
        json.dump(payload, out)

    print(f"✅ Archivo cifrado guardado en {output_path}")





#Función para descifrar un archivo con RSA
def descifrar_archivo_con_rsa(input_path, private_key_path, output_path):


    with open(input_path, "r") as f:
        payload = json.load(f)
        
    encrypted_key = bytes.fromhex(payload["key_user"])
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

        encrypted_key = bytes.fromhex(payload["key_user"])
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
        QtWidgets.QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado en:\n{save_path}")

    except Exception as e:
        #imprimir mensaje de error al descifrar
        QtWidgets.QMessageBox.critical(self, "Error", f"No se pudo descifrar el archivo:\n{str(e)}")

#+++++FUNCIONES AUXILIARES+++++FIN+++++


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()