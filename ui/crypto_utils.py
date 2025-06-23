
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class AESCBCWrapper:
    def __init__(self, key: bytes, iv: bytes = None):
        self.key = key
        self.iv = iv or os.urandom(16)

    def encrypt(self, data: bytes) -> str:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(self.iv + encrypted).decode()

    def decrypt(self, token: str) -> bytes:
        raw = base64.b64decode(token)
        iv = raw[:16]
        encrypted = raw[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    @staticmethod
    def generate_key() -> bytes:
        return os.urandom(32)
