# Import libraries
import customtkinter as ctk
import hashlib
import base64
from cryptography.fernet import Fernet
from clipboard import copy

def generate_key():
    return Fernet.generate_key()

# Example of using the generated key:
# key = generate_key()
# f = Fernet(key)
# ciphertext = f.encrypt(message.encode())

def encrypt_text(message, key):
  """
  Encrypts a message using the provided key and returns the ciphertext.
  """
  #converting into base-64 url safe
  # key = encrypt_sha(key)
  # Generate a Fernet object with the key
  f = Fernet(key)
  # Encrypt the message
  ciphertext = f.encrypt(message.encode())
  # Return the ciphertext as a string
  return ciphertext.decode()

def decrypt_text(ciphertext, key):
  """
  Decrypts a ciphertext using the provided key and returns the original message.
  """
  # Generate a Fernet object with the key
  # key = encrypt_sha(key)
  f = Fernet(key)
  # Decrypt the ciphertext
  message = f.decrypt(ciphertext.encode())
  # Return the decrypted message as a string
  return message.decode()

def encrypt_sha(key):
  """
  changing the user input key-text into sha-32 bytes
  """ 
# Convert the input string to bytes using UTF-8 encoding
  input_bytes = key.encode('utf-8')

    # Hash the input using SHA-256
  hashed_bytes = hashlib.sha256(input_bytes).digest()

    # Encode the hashed bytes into URL-safe base64
  encoded_bytes = base64.urlsafe_b64encode(hashed_bytes)
  return encoded_bytes;

def encrypt_message():
  home_frame.pack_forget()
  encrypt_frame.pack(pady=20)

def decrypt_message():
  home_frame.pack_forget()
  decrypt_frame.pack(pady=20)

def go_back_to_home():
  encrypt_frame.pack_forget()
  encrypted_frame.pack_forget()
  decrypt_frame.pack_forget()
  decrypted_frame.pack_forget()
  home_frame.pack(pady=20)

# Create main window
app = ctk.CTk()
app.geometry("1200x600")
app.title("Encryption/Decryption Tool--github.com/itsmeHrishi/")

#initialize frames
encrypted_frame = ctk.CTkFrame(master=app)
encrypted_frame.pack_forget()

decrypted_frame = ctk.CTkFrame(master=app)
decrypted_frame.pack_forget()

# Home frame
home_frame = ctk.CTkFrame(master=app)
home_frame.pack(pady=20)

button_encrypt = ctk.CTkButton(master=home_frame, text="Encrypt", command=encrypt_message)
button_encrypt.pack(pady=10)

button_decrypt = ctk.CTkButton(master=home_frame, text="Decrypt", command=decrypt_message)
button_decrypt.pack(pady=10)

# Encrypt frame (initially hidden)
encrypt_frame = ctk.CTkFrame(master=app)
encrypt_frame.pack_forget()

# Message input field
label_message = ctk.CTkLabel(master=encrypt_frame, text="Your message:")
label_message.pack(pady=5)
entry_message = ctk.CTkEntry(master=encrypt_frame)
entry_message.pack(pady=5)

# Key input field
label_key = ctk.CTkLabel(master=encrypt_frame, text="Your key:")
label_key.pack(pady=5)
entry_key = ctk.CTkEntry(master=encrypt_frame)
entry_key.pack(pady=5)

# Submit button
button_submit = ctk.CTkButton(master=encrypt_frame, text="Encrypt", command=lambda: process_encryption())
button_submit.pack(pady=10)
button_home = ctk.CTkButton(master=encrypt_frame, text="Home", command=go_back_to_home)
button_home.pack(pady=10)

def process_encryption():
  message = entry_message.get()
  # key = entry_key.get()
  key = generate_key()
  encrypted_message = encrypt_text(message, key)  # Call your encryption function
  encrypt_frame.pack_forget()

  # Encrypted message frame
  encrypted_frame = ctk.CTkFrame(master=app)
  label_encrypted = ctk.CTkLabel(master=encrypted_frame, text=f"Encrypted Message:\n{encrypted_message}")
  label_encrypted.pack(pady=5)
  button_copy = ctk.CTkButton(master=encrypted_frame, text="Copy", command=lambda: copy(encrypted_message))
  button_copy.pack(pady=5)
  label_encrypted = ctk.CTkLabel(master=encrypted_frame, text=f"Key:\n{key}")
  label_encrypted.pack(pady=5)
  button_copy = ctk.CTkButton(master=encrypted_frame, text="Copy", command=lambda: copy(key.decode()))
  button_copy.pack(pady=5)
  button_home = ctk.CTkButton(master=encrypted_frame, text="Home", command=go_back_to_home)
  button_home.pack(pady=10)
  encrypted_frame.pack(pady=10)

# Decrypt frame (initially hidden)
decrypt_frame = ctk.CTkFrame(master=app)
decrypt_frame.pack_forget()

# Message input field
label_message = ctk.CTkLabel(master=decrypt_frame, text="Message:")
label_message.pack(pady=5)
entry_message = ctk.CTkEntry(master=decrypt_frame)
entry_message.pack(pady=5)

# Key input field
label_key = ctk.CTkLabel(master=decrypt_frame, text="Your key:")
label_key.pack(pady=5)
entry_key = ctk.CTkEntry(master=decrypt_frame)
entry_key.pack(pady=5)

# Submit button
button_submit = ctk.CTkButton(master=decrypt_frame, text="Decrypt", command=lambda: process_decryption())
button_submit.pack(pady=10)
button_home = ctk.CTkButton(master=decrypt_frame, text="Home", command=go_back_to_home)
button_home.pack(pady=10)

def process_decryption():
  message = entry_message.get()
  key = entry_key.get()
  decrypted_message = decrypt_text(message, key)
  print(decrypted_message)

  decrypt_frame.pack_forget()

  # Decrypted message frame
  decrypted_frame = ctk.CTkFrame(master=app)
  label_decrypted = ctk.CTkLabel(master=decrypted_frame, text=f"Decrypted Message:\n{decrypted_message}")
  label_decrypted.pack(pady=5)
  button_home = ctk.CTkButton(master=decrypted_frame, text="Home", command=go_back_to_home)
  button_home.pack(pady=10)
  decrypted_frame.pack(pady=10)

app.mainloop()