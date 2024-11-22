import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# from Crypto.Cipher import AES

def kdf(key, info, length=32):
    return HKDF(
        algorithm = hashes.SHA256(),
        length = length,
        salt = None,
        info=info
    ).derive(key)

# encryption of plain text using AES-GCM
def encrypt(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

def decrypt(key, ciphertext):
    iv = ciphertext[:12]
    tag = ciphertext[-16:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext[12:-16]) + decryptor.finalize()

                                                             