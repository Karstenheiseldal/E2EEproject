import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class DoubleRatchet:
      def __init__(self, parameters, local_private_key = None, peer_public_key = None):
            self.parameters = parameters
            self.local_private_key = local_private_key or self.parameters.generate_private_key()
            self.local_public_key = self.local_private_key.public_key()
            self.peer_public_key = peer_public_key
            self.root_key = self._derive_shared_secret() # For initialization we only use the shared secret as the root_key
            self.sending_chain_key = None
            self.receiving_chain_key = None
            self.is_first_message = True
            self.session_length = 3

      def _derive_shared_secret(self):
            shared_secret = self.local_private_key.exchange(self.peer_public_key)
            root_key = HKDF(
                  algorithm=hashes.SHA256(),
                  length=64,
                  salt=None,
                  info=b""
            ).derive(shared_secret)
            return root_key[:32]
      def _derive_key_with_shared_secret(self, key):
            shared_secret = self.local_private_key.exchange(self.peer_public_key)
            kdf_output = HKDF(
                  algorithm=hashes.SHA256(),
                  length=64,
                  salt=None,
                  info=b""
            ).derive(key + shared_secret)
            self.root_key = kdf_output[:32]
            return kdf_output[32:]
      def ratchet_step(self, peer_public_key):
            if self.peer_public_key != peer_public_key:
                  self.peer_public_key = peer_public_key
                  self.receiving_chain_key = self._derive_key_with_shared_secret(self.root_key)
                  self.sending_chain_key = None
                  self.session_length = 3
      def update_symmetric_ratchet_sending_chain(self):
            if self.sending_chain_key is None:
                  self.sending_chain_key = self._derive_key_with_shared_secret(self.root_key)
            kdf_output = HKDF(
                  algorithm=hashes.SHA256(),
                  length=64,
                  salt=None,
                  info=b""
            ).derive(self.sending_chain_key)
            self.sending_chain_key = kdf_output[32:]
            message_key = kdf_output[:32]
            return message_key
      def update_symmetric_ratchet_receiving_chain(self):
            if self.receiving_chain_key is None:
                  self.receiving_chain_key = self._derive_key_with_shared_secret(self.root_key)
            kdf_output = HKDF(
                  algorithm=hashes.SHA256(),
                  length=64,
                  salt=None,
                  info=b""
            ).derive(self.receiving_chain_key)
            self.receiving_chain_key = kdf_output[32:]
            message_key = kdf_output[:32]
            return message_key
      def serialize_public_key(self):
            return self.local_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
      def deserialize_public_key(self, peer_public_key_bytes):
            return serialization.load_pem_public_key(peer_public_key_bytes)
      def check_and_update_keys(self):
            if self.session_length == 0:
                  self.local_private_key = self.parameters.generate_private_key()
                  self.local_public_key = self.local_private_key.public_key()
                  self.sending_chain_key = self._derive_key_with_shared_secret(self.root_key)
                  self.receiving_chain_key = None
                  self.session_length = 3
            else:
                  self.session_length = self.session_length - 1

def encrypt(key, plaintext):
      try:
            iv = os.urandom(12)
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            return iv + ciphertext + encryptor.tag
      except Exception as e:
            print(f"Error at encrypting message: {e}")

def decrypt(key, ciphertext):
      try:
            iv = ciphertext[:12]
            tag = ciphertext[-16:]
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext[12:-16]) + decryptor.finalize()
      except Exception as e:
            print(f"Error at decrypting message: {e}")
