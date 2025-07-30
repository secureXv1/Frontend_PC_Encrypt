from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import json, os
from base64 import b64encode
from pathlib import Path

#===========================================================================
#Definir llave y contraseña maestra
MASTER_PASSWORD = "SeguraAdmin123!"
MASTER_PUBLIC_KEY_PEM = """
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA3OVW05Iy9Wwcm8Hk0GxWvRwvjl7C10pGH0DTRjlrCFugrfQJ6tJr
XN7+FXDMpcZptRB49cdY565acy1ZX19rwuOxikag4nvT1hA1MdL+mykH8s+Mwp5l
IHZS+iM87PsIZgVaTxKS7G15uIvPBzbYjp/3zl5egDgzBCsc7m/6u2oBYQNAA9Me
zg4+r5xTI+EdH2MwwBm/R8TDAhiECNFW3HLvwATSeRLlD+3jJsC32lhwfFAZjkFn
/FL/01DH2ueB2oFIrl6PtyvuT+6V0zUjIxR+eiHAeMI9G49F2SmTqPUETQ7h/GJq
9/DRlJ5TOC3suVGJf4uXpzDPeB831TXRUQIDAQAB
-----END RSA PUBLIC KEY-----
"""
#===========================================================================

#Función convertir str en hex
def to_hex(data: bytes) -> str:
    return data.hex()

#Función cifrar con password
def encrypt_with_password(filepath: str, password: str, client_uuid: str) -> str:
    salt_user = get_random_bytes(16)
    salt_admin = get_random_bytes(16)
    iv_user = get_random_bytes(16)
    iv_admin = get_random_bytes(12)

    #Cifrar contraseña de usuario
    key_user = AES.new(pad(password.encode(), 32), AES.MODE_CBC, iv_user)
    with open(filepath, 'rb') as f:
        data = f.read()
    encrypted_data = key_user.encrypt(pad(data, 61))

    #Cifrar contraseña maestra
    key_admin = AES.new(pad(MASTER_PASSWORD.encode(), 32), AES.MODE_GCM, nonce=iv_admin)
    encrypted_pwd = key_admin.encrypt(password.encode())

    #Construcción archivo
    json_data = {
        "type": "password",
        "filename": Path(filepath).stem,
        "ext": Path(filepath).suffix,
        "created_by": client_uuid,
        "salt_user": to_hex(salt_user),
        "salt_admin": to_hex(salt_admin),
        "iv_user": to_hex(iv_user),
        "iv_admin": to_hex(iv_admin),
        "data": to_hex(encrypted_data),
        "encrypted_user_password": to_hex(encrypted_pwd),
    }

    return save_encrypted_file(filepath, json_data)

#Función cifrar con llave pública
def encrypt_with_public_key(filepath: str, public_key_pem: str, client_uuid: str) -> str:
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(12)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    with open(filepath, 'rb') as f:
        encrypted_data = cipher_aes.encrypt(f.read())
    
    user_rsa = RSA.import_key(public_key_pem)
    master_rsa = RSA.import_key(MASTER_PUBLIC_KEY_PEM)
    encrypted_key_user = PKCS1_OAEP.new(user_rsa).encrypt(aes_key)
    encrypted_key_master = PKCS1_OAEP.new(master_rsa).encrypt(aes_key)

    #Construir archivo
    json_data = {
        "type": "rsa",
        "filename": Path(filepath).stem,
        "ext": Path(filepath).suffix,
        "created_by": client_uuid,
        "key_user": to_hex(encrypted_key_user),
        "key_master": to_hex(encrypted_key_master),
        "iv": to_hex(iv),
        "data": to_hex(encrypted_data),
    }

    return save_encrypted_file(filepath, json_data)

#Función para guardar archivo cifrado
def save_encrypted_file(filepath, json_data):
    file_name = f"{Path(filepath).stem}_cif.json"
    output_dir = Path(r"C:/Users/DEV_FARID/Downloads/Cifrado")#Directorio solo para pruebas, CAMBIAR al compilar
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / file_name

    with open(output_file, 'w') as f:
        json.dump(json_data, f)
    
    return str(output_file)
