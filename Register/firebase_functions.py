from firebase_admin import db


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
      
# setting up keys for the user by uploading to firebase's db 
def upload_key(username, identity_key, signed_pre_key, one_time_keys):
      ref = db.reference(f"users/{username}/keys")
      ref.set({
            "identity_key": identity_key,
            "signed_pre_key": signed_pre_key,
            "one_time_pre_keys": one_time_keys
      })

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

def fetch_message(username):
      ref = db.reference(f"messages/{username}")
      return ref.get() or {} # returns empty dictionary if no messages

def delete_message(username):
      ref = db.reference(f"messages/{username}")
      ref.delete()