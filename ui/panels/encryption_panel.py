from PyQt5.QtWidgets import QWidget, QVBoxLayout, QPushButton, QFileDialog, QMessageBox, QGroupBox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64, json, os

# Clave pública maestra
MASTER_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmwF4EDZIm66+kJZlTTiV
TtxAxr60j2CmxLfLBfdvuJdKadmV4i6yatfRSeS+ZGCAFBKwb+jHNNWv2VyWDyGO
3vWqBA4OI69jCFF1R9cOJY4bzDmxB1pB9KgfVX3HtvyMe3Zu8q7+6s6IcthHmaoK
xcXLKTjcsQlVb7hcWMVYaaSwyiPxtRnF/Tk42ys0eps66rM9EKi+K6/mnSzjhquS
XlGY+O2HxGq+H3K8kP8R6iLU09mm5Q11PBoir12wiHQ8m8NiTKzCLAOAt2CCBpyu
UIu1Bie1A04MPaKuvKXpnML5Ib9LGiXcjI6kvjOXhrj1dT8ES8JALGJWnohYZjkJ
0wIDAQAB
-----END PUBLIC KEY-----"""

class EncryptionPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        layout = QVBoxLayout(self)

        group = QGroupBox("Operaciones de Cifrado")
        group_layout = QVBoxLayout()

        self.add_button(layout, "🔐 Crear Llaves", self.on_create_keys)
        self.add_button(layout, "📦 Cifrar Archivo", self.on_encrypt_file)
        self.add_button(layout, "🔓 Descifrar Archivo", self.on_decrypt_file)
        self.add_button(layout, "🖼️ Ocultar Archivo Cifrado", self.on_hide_file)
        self.add_button(layout, "🔍 Extraer Archivo Oculto", self.on_extract_hidden_file)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
        layout.addStretch()

    def add_button(self, layout, label, callback):
        btn = QPushButton(label)
        btn.setFixedHeight(40)
        btn.clicked.connect(callback)
        layout.addWidget(btn)

    def on_create_keys(self):
        path, _ = QFileDialog.getSaveFileName(self, "Guardar clave (nombre base)", "", "PEM Files (*.pem)")
        if not path:
            return
        base = path.rsplit(".", 1)[0]
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(f"{base}_private.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(f"{base}_public.pem", "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        QMessageBox.information(self, "Éxito", f"Claves generadas en:\n{base}_private.pem\n{base}_public.pem")

    def on_encrypt_file(self):
        input_file, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo a cifrar")
        if not input_file:
            return
        public_key_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar clave pública del destinatario")
        if not public_key_path:
            return
        output_path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo cifrado", "archivo_cifrado.json")
        if not output_path:
            return
        try:
            with open(input_file, "rb") as f:
                file_data = f.read()
            _, ext = os.path.splitext(input_file)
            payload = {
                "ext": ext,
                "content": base64.b64encode(file_data).decode("utf-8")
            }
            serialized = json.dumps(payload).encode("utf-8")
            aes_key = Fernet.generate_key()
            fernet = Fernet(aes_key)
            encrypted_data = fernet.encrypt(serialized)

            with open(public_key_path, "rb") as f:
                pub_user = serialization.load_pem_public_key(f.read())
            pub_master = serialization.load_pem_public_key(MASTER_PUBLIC_KEY_PEM)
            encrypted_key_user = pub_user.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            encrypted_key_master = pub_master.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

            final_payload = {
                "key_user": encrypted_key_user.hex(),
                "key_master": encrypted_key_master.hex(),
                "data": encrypted_data.hex(),
                "ext": ext
            }
            with open(output_path, "w") as f:
                json.dump(final_payload, f)
            QMessageBox.information(self, "Éxito", f"Archivo cifrado guardado en:\n{output_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_decrypt_file(self):
        private_key_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar tu clave privada")
        if not private_key_path:
            return
        encrypted_file, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo cifrado")
        if not encrypted_file:
            return
        save_path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo descifrado como", "descifrado")
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
                aes_key = private_key.decrypt(encrypted_key_user, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            except:
                aes_key = private_key.decrypt(encrypted_key_master, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            decrypted_data = Fernet(aes_key).decrypt(encrypted_data)
            original = json.loads(decrypted_data.decode("utf-8"))
            ext = original.get("ext", ".bin")
            if not save_path.endswith(ext):
                save_path += ext
            with open(save_path, "wb") as f:
                f.write(base64.b64decode(original["content"]))
            QMessageBox.information(self, "Éxito", f"Archivo descifrado guardado como:\n{save_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_hide_file(self):
        json_file, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo cifrado", "", "JSON (*.json)")
        if not json_file:
            return
        container_file, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo contenedor")
        if not container_file:
            return
        ext = os.path.splitext(container_file)[1]
        out_file, _ = QFileDialog.getSaveFileName(self, "Guardar archivo oculto", f"oculto{ext}", f"Contenedor (*{ext})")
        if not out_file:
            return
        try:
            with open(container_file, "rb") as c:
                cont_data = c.read()
            with open(json_file, "rb") as j:
                cipher_data = j.read()
            with open(out_file, "wb") as f:
                f.write(cont_data + b"<<--BETTY_START-->>" + cipher_data)
            QMessageBox.information(self, "Éxito", f"Archivo oculto guardado como:\n{out_file}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def on_extract_hidden_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Seleccionar archivo contenedor")
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            idx = content.find(b"<<--BETTY_START-->>")
            if idx == -1:
                raise Exception("No se encontró contenido oculto.")
            hidden_data = content[idx + len(b"<<--BETTY_START-->>") :]
            ext = ".json"
            try:
                parsed = json.loads(hidden_data.decode())
                ext = parsed.get("ext", ".json")
            except:
                pass
            out_path, _ = QFileDialog.getSaveFileName(self, "Guardar archivo extraído", f"extraido{ext}", f"Archivo Extraído (*{ext})")
            if not out_path:
                return
            with open(out_path, "wb") as f:
                f.write(hidden_data)
            QMessageBox.information(self, "Éxito", f"Archivo extraído en:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
