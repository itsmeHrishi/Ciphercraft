import hashlib
import base64
import time
from cryptography.fernet import Fernet
def encrypt_text(message, key):
  """
  Encrypts a message using the provided key and returns the ciphertext.
  """
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
  f = Fernet(key)
  # Decrypt the ciphertext
  message = f.decrypt(ciphertext.encode())
  # Return the decrypted message as a string
  return message.decode()

def encrypt_sha(key):
  """
  changing the user input text into sha-32 bytes
  """ 
# Convert the input string to bytes using UTF-8 encoding
  input_bytes = key.encode('utf-8')

    # Hash the input using SHA-256
  hashed_bytes = hashlib.sha256(input_bytes).digest()

    # Encode the hashed bytes into URL-safe base64
  encoded_bytes = base64.urlsafe_b64encode(hashed_bytes)
  return encoded_bytes;


def menu():
  """
  Displays the CLI menu and returns user choice.
  """
  print("Welcome to the Encryption/Decryption Tool!")
  print("1. Encrypt Text")
  print("2. Decrypt Text")
  choice = input("Enter your choice: ")
  return choice

while True:
  choice = menu()
  if choice == "1":
    message = input("Enter your message: ")
    key = input("Enter your encryption key: ")
    key = encrypt_sha(key);
    ciphertext = encrypt_text(message, key)
    print("Encrypted Text:", ciphertext)
  elif choice == "2":
    ciphertext = input("Enter the ciphertext: ")
    key = input("Enter the decryption key: ")
    key = encrypt_sha(key)
    message = decrypt_text(ciphertext, key)
    print("Decrypted Message:", message)
  else:
    print("Invalid choice. Please try again.")
    continue

  # Prompt to continue or exit
  stop = input("Continue (y/n)? ").lower()
  if stop == "n":
    print("Exiting program in 3 Seconds...")
    time.sleep(3)
    break

time.sleep(5)