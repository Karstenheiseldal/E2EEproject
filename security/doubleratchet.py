import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey, Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# from Crypto.Cipher import AES

def kdf(chain_key, length=32):
    return HKDF(
        algorithm = hashes.SHA256(),
        length = length,
        salt = None,
        info=b"chain_key_derivation",
    ).derive(chain_key)

def initialize_session(sender_private_key, receiver_key_bundle):
    dh1 = sender_private_key.exchange(receiver_key_bundle["identity_key"])
    dh2 = sender_private_key.exchange(receiver_key_bundle["signed_pre_key"])

    shared_key = dh1 + dh2
    root_key = kdf(shared_key, b"root_key")
    return root_key

# encryption of plain text using AES-GCM
def encrypt(key, plaintext):
    print(f"Key in encryptor: {key}")
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    print("before cipher")
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    print("After cipher")
    print(f"IV: {iv}, CipherText: {ciphertext}, Encryptor.tag: {encryptor.tag}")
    print(f"Result: {iv + ciphertext + encryptor.tag}")
    return iv + ciphertext + encryptor.tag

def decrypt(key, ciphertext):
    try:
        print(f"Key in decryptor: {key}")
        print("Decrypt?")
        iv = ciphertext[:12]
        print("Decrypt2?")
        tag = ciphertext[-16:]
        print("Decrypt3?")
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        print("Decrypt4?")
        decryptor = cipher.decryptor()
        print("Decrypt5?")
        print(f"Ciphertext in decryptor: {ciphertext}")
        return decryptor.update(ciphertext[12:-16]) + decryptor.finalize()
    except Exception as e:
        print(f"Error at decrypting: {e}")
