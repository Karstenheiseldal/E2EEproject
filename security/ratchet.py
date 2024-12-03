from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from security.doubleratchet import encrypt, decrypt

def hkdf(key, salt, info, length=32):
      return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info).derive(key)

class Ratchet:
      def __init__(self, root_key, private_key):
            self.root_key = root_key
            self.sending_chain_key = None
            self.receiving_chain_key = None
            self.skipped_keys = {}
            self.local_private_key = private_key

      def dh_ratchet(self, remote_public_key):
            shared_secret = self.derive_shared_secret(remote_public_key)
            self.root_key = hkdf(shared_secret, self.root_key, b"root")
            #self.sending_chain_key = hkdf(self.root_key, b"0", b"sending-chain")
            #self.receiving_chain_key = hkdf(self.root_key, b"1", b"receiving-chain")
      def symmetric_ratchet(self):
            """Perform a symmetric ratchet step."""
            self.message_key = hkdf(self.ratchet_key, None, info=b"message_key")
            self.root_key = hkdf(self.root_key, None, info=b"next_root_key")
      """
      def symmetric_ratchet(self, chain_key):
            new_chain_key = hkdf(chain_key, b"0", b"chain")
            message_key = hkdf(chain_key, b"1", b"message", length=16)  # 16 bytes for AES key
            return new_chain_key, message_key
      """
      def get_message_key(self, is_sending):
            if is_sending:
                  self.sending_chain_key, message_key = self.symmetric_ratchet(self.sending_chain_key)
            else:
                  self.receiving_chain_key, message_key = self.symmetric_ratchet(self.receiving_chain_key)
            return message_key
      def derive_shared_secret(self, peer_public_key):
            shared_key = self.local_private_key.exchange(peer_public_key)
            hkdf = HKDF(
                  algorithm=hashes.SHA256(),
                  length=32,
                  salt=None,
                  info=b'handshake data')
            return hkdf.derive(shared_key)
      def encrypt_message(self, plaintext):
            """Encrypt a message using the current message key."""
            self.symmetric_ratchet()
            return encrypt(self.message_key, plaintext)

      def decrypt_message(self, ciphertext):
            """Decrypt a message using the current message key."""
            return decrypt(self.message_key, ciphertext)
