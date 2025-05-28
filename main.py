from PyQt5 import QtWidgets, QtGui, QtCore
import sys
import os, json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class TunnelPanel(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setLayout(QtWidgets.QVBoxLayout())

        # Lista de túneles
        self.tunnel_list = QtWidgets.QListWidget()
        self.layout().addWidget(QtWidgets.QLabel("🛡 Mis Túneles"))
        self.layout().addWidget(self.tunnel_list)

        # Botones para crear/conectarse
        btn_layout = QtWidgets.QHBoxLayout()
        self.btn_create = QtWidgets.QPushButton("➕ Crear Túnel")
        self.btn_connect = QtWidgets.QPushButton("🔌 Conectarse")
        btn_layout.addWidget(self.btn_create)
        btn_layout.addWidget(self.btn_connect)
        self.layout().addLayout(btn_layout)

        # Área de chat
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

        # Conectar acciones
        self.btn_create.clicked.connect(self.crear_tunel)
        self.btn_connect.clicked.connect(self.conectarse_tunel)
        self.btn_send.clicked.connect(self.enviar_mensaje)

    def crear_tunel(self):
        nombre, ok = QtWidgets.QInputDialog.getText(self, "Crear Túnel", "Nombre del túnel:")
        if ok and nombre.strip():
            self.tunnel_list.addItem(nombre.strip())
            self.chat_area.append(f"🔐 Túnel '{nombre.strip()}' creado.")

    def conectarse_tunel(self):
        item = self.tunnel_list.currentItem()
        if item:
            tunel = item.text()
            self.chat_area.show()
            self.chat_input.show()
            self.btn_send.show()
            self.chat_area.append(f"✅ Te has conectado al túnel '{tunel}'.")

    def enviar_mensaje(self):
        mensaje = self.chat_input.text().strip()
        if mensaje:
            self.chat_area.append(f"🧑 Tú: {mensaje}")
            self.chat_input.clear()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("BETTY - Simulador PGP Educativo")
        self.setGeometry(100, 100, 1000, 600)

        # Layout principal
        central_widget = QtWidgets.QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QtWidgets.QHBoxLayout(central_widget)

        # Panel izquierdo: túneles y chat
        self.left_panel = TunnelPanel()

        # Panel derecho: opciones principales
        self.right_panel = QtWidgets.QVBoxLayout()
        self.add_menu_button("🔐 Crear Llaves", self.on_create_keys)
        self.add_menu_button("📦 Cifrar Archivo", self.on_encrypt_file)
        self.add_menu_button("🔓 Descifrar Archivo", self.on_decrypt_file)
        self.add_menu_button("🖼️ Ocultar Archivo Cifrado", self.on_hide_file)
        self.add_menu_button("🔍 Extraer y Descifrar Archivo", self.on_extract_hidden_file)
        self.right_panel.addStretch()

        # Integrar ambos paneles
        main_layout.addWidget(self.left_panel, 3)
        main_layout.addLayout(self.right_panel, 2)

    def add_menu_button(self, label, callback):
        button = QtWidgets.QPushButton(label)
        button.setFixedHeight(40)
        button.clicked.connect(callback)
        self.right_panel.addWidget(button)

    # Funciones placeholder
    def on_create_keys(self):
        options = QtWidgets.QFileDialog.Options()
        file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar clave (nombre base)", "", "PEM Files (*.pem);;All Files (*)", options=options)
        
        if not file_path:
            return  # Cancelado por el usuario
        
        base_name = file_path.rsplit(".", 1)[0]  # Quitar extensión si la hay
        
        # Generar clave privada
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Serializar y guardar clave privada
        with open(f"{base_name}_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
            # Serializar y guardar clave pública
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

        # Seleccionar clave pública
        public_key_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar clave pública (.pem)", "", "Claves Públicas (*.pem);;All Files (*)")
             
             
        if not public_key_file:
            return

    # Seleccionar ruta de salida
        output_file, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo cifrado", "", "Archivo Cifrado (*.json)")

        if not output_file:
            return

        try:
            cifrar_archivo_con_rsa(input_file, public_key_file, output_file)
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo cifrado guardado en:\n{output_file}")
            self.left_panel.chat_area.append("📦 Archivo cifrado exitosamente.")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo cifrar el archivo:\n{e}")



    #Función para descifrar
    def on_decrypt_file(self):
        #Elegir documento a descifrar
        input_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado (.json)", "", "Archivos Cifrados (*.json);;All Files (*)")
        
        if not input_file:
            return
        
        # Seleccionar clave privada
        private_key_file, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar clave privada (.pem)", "", "Claves Privadas (*.pem);;All Files (*)")
        
        if not private_key_file:
            return
        
        # Seleccionar ubicación de salida
        output_file, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo descifrado", "", "Todos los archivos (*)")
        
        if not output_file:
            return
        
        try:
            descifrar_archivo_con_rsa(input_file, private_key_file, output_file)
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo descifrado guardado en:\n{output_file}")
            self.left_panel.chat_area.append("🔓 Archivo descifrado exitosamente.")

        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo descifrar el archivo:\n{e}")
    

    #Función para descifrar archivo extraido
    def descifrar_archivo_extraido(self, file_path):
        
        # Seleccionar clave privada
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
        #Seleccionar archivo contenedor (imagen, audio, PDF, etc.)
        contenedor_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor (imagen, PDF, ZIP, etc.)", "", "Todos los archivos (*)")
        
        if not contenedor_path:
            return
        
        # Seleccionar archivo cifrado (.json)
        cifrado_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo cifrado a ocultar", "", "Archivos JSON (*.json);;Todos los archivos (*)")
        
        if not cifrado_path:
            return
        
        # Obtener extensión original del archivo contenedor
        base_name, ext = os.path.splitext(contenedor_path)
             
        # Guardar el archivo combinado
        salida_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Guardar archivo oculto", base_name + "_reparado" + ext, f"Archivos (*{ext})")
        
        if not salida_path:
            return
        
        try:
            with open(contenedor_path, "rb") as f1, open(cifrado_path, "rb") as f2:
                contenedor_data = f1.read()
                cifrado_data = f2.read()
            
            with open(salida_path, "wb") as out:
                out.write(contenedor_data)
                out.write(b"<<BETTY_HIDDEN>>")
                out.write(cifrado_data)
            
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo oculto guardado en:\n{salida_path}")
        
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo ocultar el archivo:\n{e}")
    
    #Función para extraer archivo y descifrar
    def on_extract_hidden_file(self):
        contenedor_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, "Seleccionar archivo contenedor", "", "All Files (*)"
        )

        if not contenedor_path:
            return
        
        #Leer archivo contenedor y buscar delimitador
        try:
            with open(contenedor_path, "rb") as f:
                contenido = f.read()
            
            delimiter = b"<<BETTY_HIDDEN>>"
            idx = contenido.find(delimiter)
            if idx == -1:
                QtWidgets.QMessageBox.warning(self, "⚠️ No encontrado", "No se encontró contenido oculto.")
                return
            
            contenido_original = contenido[:idx]
            datos_ocultos = contenido[idx + len(delimiter):]

            #Guardar el archivo cifrado extraído
            output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Guardar archivo extraído", "", "Archivo Cifrado (*.json)"
            )

            if not output_path:
                return
            
            with open(output_path, "wb") as out:
                out.write(datos_ocultos)
            
            QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo extraído y guardado en:\n{output_path}")

            #Preguntar si desea descifrar ahora
            reply = QtWidgets.QMessageBox.question(
                self, "¿Descifrar ahora?",
                "¿Deseas proceder con el descifrado del archivo extraído?",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No
            )

            if reply == QtWidgets.QMessageBox.Yes:
                self.descifrar_archivo_extraido(output_path)
        
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo extraer el archivo:\n{e}")

            
          
#****FUNCIONES AUXILIARES*****INICIO******

#Función para cifrar un archivo con RSA
def cifrar_archivo_con_rsa(input_path, public_key_path, output_path):
    with open(input_path, "rb") as f:
        data = f.read()
    
    # Obtener extensión original
    extension = os.path.splitext(input_path)[1]
            
    #Generar claves RSA
    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(data)

    #Cargar clave pública
    with open(public_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())

    
    #Cifrar clave AES con RSA
    encrypted_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    #Guardar en JSON
    payload = {
        "key": encrypted_key.hex(),
        "data": encrypted_data.hex(),
        "ext": extension  # ← guardar la extensión original
    }

    with open(output_path, "w") as out:
        json.dump(payload, out)


#Función para descifrar un archivo con RSA
def descifrar_archivo_con_rsa(input_path, private_key_path, output_path):
    with open(input_path, "r") as f:
        payload = json.load(f)
    
    encrypted_key = bytes.fromhex(payload["key"])
    encrypted_data = bytes.fromhex(payload["data"])
    extension = payload.get("ext", "")  # ← recuperar la extensión original

    # Cargar clave privada
    with open(private_key_path, "rb") as f:
        priv_key = serialization.load_pem_private_key(f.read(), password=None)

    # Descifrar clave AES
    aes_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Descifrar archivo con AES
    fernet = Fernet(aes_key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Añadir extensión original si no está presente
    if extension and not output_path.endswith(extension):
        output_path += extension

    with open(output_path, "wb") as f:
         f.write(decrypted_data)

#Función para ocultar archivo cifrado en un contenedor
def ocultar_archivo_en_contenedor(contenedor_path, archivo_oculto_path, salida_path):
    with open(contenedor_path, "rb") as contenedor:
        contenedor_data = contenedor.read()

    with open(archivo_oculto_path, "rb") as archivo_oculto:
        datos_ocultos = archivo_oculto.read()

    #Añade una firma
    firma = b"<<BETTY_HIDDEN>>"

    with open(salida_path, "wb") as salida:
        salida.write(contenedor_data)
        salida.write(firma)
        salida.write(datos_ocultos) 

#Función para descifrar archivo extraido
def descifrar_archivo_extraido(self, encrypted_path):
    private_key_path, _ = QtWidgets.QFileDialog.getOpenFileName(
        self, "Seleccionar clave privada (.pem)", "", "PEM Files (*.pem)"
    )

    if not private_key_path:
        return
    
    output_path, _ = QtWidgets.QFileDialog.getSaveFileName(
        self, "Guardar archivo descifrado", "", "All Files (*)"
    )

    if not output_path:
        return
    
    try:
        descifrar_archivo_con_rsa(encrypted_path, private_key_path, output_path)
        QtWidgets.QMessageBox.information(self, "✅ Éxito", f"Archivo descifrado y guardado en:\n{output_path}")
    except Exception as e:
        QtWidgets.QMessageBox.critical(self, "❌ Error", f"No se pudo descifrar:\n{e}")

#****FUNCIONES AUXILIARES*****INICIO******


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()