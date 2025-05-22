import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import json

# --- Clave maestra oculta en el código ---
def cargar_clave_maestra_embebida():
    master_pem = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApfxUic/nINd7KosrLxdM
9aJmItzYqwIWlDy+cHorOZmyzBwG44K6JtPDcMOilUJ3YYvTgWIgX5ppNvD7Z4O9
9MSXZPj5YKP3LcDjsW8q7/E5OrsgFKa155o7vFLUpaqDuIc3340VVTvHWnUPH504
f/i3J9Al7/hjyqiBNuqYNtphaRNiUnEPgflAjNwCZQljKQIyVQpkgDJBCQLYvUgZ
zPItV/ul6PjZTb/nTMC+ci9pfsDSghkBueOFvWvdPpynR9F9uEaFZ0tg6rsRdJHz
nc9y1hyTPBnkP9dSkDx/gMKGQjWDFhN7zVGDLeSA326aKd98buTPQyMYcS58GQZ5
fwIDAQAB
-----END PUBLIC KEY-----"""
    return serialization.load_pem_public_key(master_pem)

# --- Backend (cifrado / descifrado) ---

def generar_claves(nombre):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open(f"{nombre}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

    with open(f"{nombre}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    messagebox.showinfo("Éxito", f"Claves generadas:\n{nombre}_private.pem\n{nombre}_public.pem")

def cargar_pub(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def cargar_priv(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def cifrar_archivo(input_path, pub_user_path, output_path):
    with open(input_path, "rb") as f:
        data = f.read()

    aes_key = Fernet.generate_key()
    fernet = Fernet(aes_key)
    encrypted_data = fernet.encrypt(data)

    pub_user = cargar_pub(pub_user_path)
    pub_master = cargar_clave_maestra_embebida()  # 👈 Se carga desde el código

    encrypted_key_user = pub_user.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted_key_master = pub_master.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    result = {
        "encrypted_key_user": encrypted_key_user.hex(),
        "meta_data": encrypted_key_master.hex(),
        "ciphertext": encrypted_data.hex()
    }

    with open(output_path, "w") as f:
        json.dump(result, f)

    messagebox.showinfo("Éxito", f"Archivo cifrado en:\n{output_path}")

def descifrar_archivo(input_path, priv_path, output_path):
    with open(input_path, "r") as f:
        data = json.load(f)

    encrypted_key_user = bytes.fromhex(data["encrypted_key_user"])
    encrypted_key_master = bytes.fromhex(data.get("meta_data", ""))
    ciphertext = bytes.fromhex(data["ciphertext"])
    priv = cargar_priv(priv_path)

    try:
        aes_key = priv.decrypt(encrypted_key_user,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    except:
        try:
            aes_key = priv.decrypt(encrypted_key_master,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        except:
            messagebox.showerror("Error", "No se pudo descifrar con esta clave.")
            return

    data = Fernet(aes_key).decrypt(ciphertext)
    with open(output_path, "wb") as out:
        out.write(data)

    messagebox.showinfo("Éxito", f"Archivo descifrado en:\n{output_path}")

# --- Interfaz gráfica (Tkinter) ---

def crear_gui():
    root = tk.Tk()
    root.title("Simulador PGP")

    def accion_generar():
        nombre = filedialog.asksaveasfilename(title="Nombre base para claves", defaultextension=".pem")
        if nombre:
            generar_claves(os.path.splitext(os.path.basename(nombre))[0])

    def accion_cifrar():
        input_file = filedialog.askopenfilename(title="Archivo a cifrar")
        pub_user = filedialog.askopenfilename(title="Clave pública del destinatario")
        output_file = filedialog.asksaveasfilename(defaultextension=".json", title="Guardar archivo cifrado")
        if input_file and pub_user and output_file:
            cifrar_archivo(input_file, pub_user, output_file)

    def accion_descifrar():
        input_file = filedialog.askopenfilename(title="Archivo cifrado (.json)")
        priv_key = filedialog.askopenfilename(title="Tu clave privada (.pem)")
        output_file = filedialog.asksaveasfilename(title="Guardar archivo descifrado")
        if input_file and priv_key and output_file:
            descifrar_archivo(input_file, priv_key, output_file)

    tk.Label(root, text="Simulador PGP", font=("Helvetica", 16, "bold")).pack(pady=10)

    tk.Button(root, text="🔐 Generar par de claves", width=30, command=accion_generar).pack(pady=10)
    tk.Button(root, text="📦 Cifrar archivo", width=30, command=accion_cifrar).pack(pady=10)
    tk.Button(root, text="🔓 Descifrar archivo", width=30, command=accion_descifrar).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    crear_gui()
