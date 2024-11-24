from firebase_admin import db
from security.doubleratchet import encrypt, kdf, decrypt
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


# Functions to interact with Firebase
def signup_user(username, password, ip, port):
      ref = db.reference("users")
      # Username already exists
      if ref.child(username).get() is not None:
            return False  # Username already exists
      ref.child(username).set({"password": password, "ip": ip, "port": port})
      return True

def login_user(username, password, ip, port):
      ref = db.reference(f"users/{username}")
      user_data = ref.get()
      if user_data is not None and user_data["password"] == password:
            ref.set({"password": password, "ip": ip, "port": port})
      return user_data is not None and user_data["password"] == password

def get_users():
      users_ref = db.reference("users")
      if users_ref is not None:
            return users_ref.get()
      
def generate_prekey():
      identity_key = X25519PrivateKey.generate()
      signed_pre_key = X25519PrivateKey.generate()
      one_time_keys = [X25519PrivateKey.generate() for _ in range(5)]
      return {
            "identity_key": identity_key,
            "signed_pre_key": signed_pre_key,
            "one_time_keys": [key.public_key().public_bytes() for key in one_time_keys],
            "identity_public": identity_key.public_key().public_bytes,
            "signed_pre_public": signed_pre_key.public_key().public_bytes,
      }
      
# setting up keys for the user by uploading to firebase's db 
def generate_key(username, identity_key, signed_pre_key, one_time_keys):
      ref = db.reference(f"users/{username}/keys")
      ref.set({
            "identity_key": identity_key,
            "signed_pre_key": signed_pre_key,
            "one_time_pre_keys": one_time_keys
      })

# registering user with keys
def upload_user_with_keys(username, password, ip, port):
      if signup_user(username, password, ip, port):
            key_bundle = generate_key()
            generate_key(username, key_bundle["identity_public"], key_bundle["signed_pre_public"], key_bundle["one_time_keys"])
            return True
      return False


# retrieving keys
def fetch_key(username):
      ref = db.reference(f"users/{username}/keys")
      return ref.get()


def send_message(sender, receiver, ciphertext):
      ref = db.reference(f"messages/{receiver}")
      ref.push({
            "from": sender,
            "ciphertext": ciphertext
      })

# encrypting the message
def send_encrypted_message(sender, receiver, plaintext, session_state):
      ciphertext = encrypt(session_state["chain_key"], plaintext.encode())

      # sending the encrypted message to Firebase
      send_message(sender, receiver, ciphertext)

      # deriving the next chain key
      session_state["chain_key"] = kdf(session_state["chain_key"])

def fetch_message(username):
      ref = db.reference(f"messages/{username}")
      return ref.get() or {} # returns empty dictionary if no messages

def decrypt_message(ciphertext, session_state):
      plaintext = decrypt(session_state["chain_key"], ciphertext)

      # updating chain key for any future messages
      session_state["chain_key"] = kdf(session_state["chain_key"])
      return plaintext

def delete_message(username):
      ref = db.reference(f"messages/{username}")
      ref.delete()

def fetch_and_decrypt_message(username, session_state, ciphertext):
      messages = fetch_message(username) # to fetch all the messages
      if not messages:
            print("Hmm...no messages...")
            return
      
      for msg_data in messages.values(): # iterating through all message data
            sender = msg_data["from"]
            ciphertext = msg_data["ciphertext"]

            try: 
                  plaintext = decrypt_message(ciphertext, session_state)
                  print(f"Message from {sender}: {plaintext.decode()}")
            except Exception as e:
                  print (f"Error decrypting message from {sender}: {e}")
      delete_message(username)          