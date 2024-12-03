from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dh
import os

# --- Utilities ---

def hkdf(input_key_material, salt, info=b"ratchet", length=32):
      """HKDF: Derive a key."""
      return HKDF(
            algorithm=SHA256(),
            length=length,
            salt=salt,
            info=info,
      ).derive(input_key_material)

def encrypt(key, plaintext):
      """Encrypt with AES-GCM."""
      iv = os.urandom(12)
      cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
      encryptor = cipher.encryptor()
      ciphertext = encryptor.update(plaintext) + encryptor.finalize()
      return iv + ciphertext + encryptor.tag

def decrypt(key, ciphertext):
      """Decrypt with AES-GCM."""
      iv = ciphertext[:12]
      tag = ciphertext[-16:]
      cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
      decryptor = cipher.decryptor()
      return decryptor.update(ciphertext[12:-16]) + decryptor.finalize()

# --- Double Ratchet ---

class DoubleRatchet:
      def __init__(self, shared_secret):
            self.ratchet_key = shared_secret  # Initial shared secret
            self.message_key = None

      def dh_ratchet(self, shared_secret):
            """Update ratchet key with new DH shared secret."""
            self.ratchet_key = hkdf(shared_secret, self.ratchet_key)

      def symmetric_ratchet(self):
            """Perform a symmetric ratchet step."""
            self.message_key = hkdf(self.ratchet_key, None, info=b"message_key")
            self.ratchet_key = hkdf(self.ratchet_key, None, info=b"next_ratchet_key")

      def encrypt_message(self, plaintext):
            """Encrypt a message using the current message key."""
            self.symmetric_ratchet()
            return encrypt(self.message_key, plaintext)

      def decrypt_message(self, ciphertext):
            """Decrypt a message using the current message key."""
            return decrypt(self.message_key, ciphertext)


# --- Example Usage ---

# Generate DH parameters and keys for Alice and Bob
parameters = dh.generate_parameters(generator=2, key_size=2048)
alice_private_key = parameters.generate_private_key()
bob_private_key = parameters.generate_private_key()

alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()

# Exchange DH public keys and compute shared secret
alice_shared_secret = alice_private_key.exchange(bob_public_key)
bob_shared_secret = bob_private_key.exchange(alice_public_key)

# Derive initial shared secret using HKDF
alice_initial_secret = hkdf(alice_shared_secret, salt=None, info=b"initial_secret")
bob_initial_secret = hkdf(bob_shared_secret, salt=None, info=b"initial_secret")

# Initialize Double Ratchets
alice_ratchet = DoubleRatchet(alice_initial_secret)
bob_ratchet = DoubleRatchet(bob_initial_secret)

# --- Communication ---

# Alice sends a message
message = b"Hello, Bob!"
ciphertext = alice_ratchet.encrypt_message(message)

# Bob decrypts the message
plaintext = bob_ratchet.decrypt_message(ciphertext)
assert plaintext == message  # Ensure correctness
print("Decrypted Message (Bob):", plaintext)

# Bob replies to Alice
reply = b"Hi, Alice!"
ciphertext_reply = bob_ratchet.encrypt_message(reply)

# Alice decrypts the reply
plaintext_reply = alice_ratchet.decrypt_message(ciphertext_reply)
assert plaintext_reply == reply  # Ensure correctness
print("Decrypted Reply (Alice):", plaintext_reply)
