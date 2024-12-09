from firebase_admin import db


def signup_user(username, password, ip, port):
      ref = db.reference("users")
      if ref.child(username).get() is not None:
            return False
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
