from firebase_admin import db


# Functions to interact with Firebase
def signup_user(username, password):
      ref = db.reference("users")
      # Username already exists
      if ref.child(username).get() is not None:
            return False  # Username already exists
      ref.child(username).set({"password": password})
      return True

def login_user(username, password, ip, port):
      ref = db.reference(f"users/{username}")
      ref.child(username).set({"ip": ip, "port": port})
      user_data = ref.get()
      return user_data is not None and user_data["password"] == password
