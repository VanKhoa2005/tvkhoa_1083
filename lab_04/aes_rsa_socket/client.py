from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

import socket
import threading


# =========================
# CLIENT CONFIG
# =========================

HOST = "localhost"
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))


# =========================
# GENERATE CLIENT RSA KEY
# =========================

client_key = RSA.generate(2048)


# =========================
# RECEIVE SERVER PUBLIC KEY
# =========================

server_public_key_data = client_socket.recv(2048)
server_public_key = RSA.import_key(server_public_key_data)


# =========================
# SEND CLIENT PUBLIC KEY TO SERVER
# =========================

client_public_key = client_key.publickey().export_key(format="PEM")
client_socket.send(client_public_key)


# =========================
# RECEIVE ENCRYPTED AES KEY
# =========================

encrypted_aes_key = client_socket.recv(2048)


# =========================
# DECRYPT AES KEY
# =========================

cipher_rsa = PKCS1_OAEP.new(client_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)


# =========================
# AES ENCRYPT / DECRYPT
# =========================

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(
        pad(message.encode("utf-8"), AES.block_size)
    )

    return cipher.iv + ciphertext


def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_message = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    )

    return decrypted_message.decode("utf-8")


# =========================
# RECEIVE MESSAGE FROM SERVER
# =========================

def receive_messages():
    while True:
        try:
            encrypted_message = client_socket.recv(4096)

            if not encrypted_message:
                break

            decrypted_message = decrypt_message(aes_key, encrypted_message)

            print("\nReceived:", decrypted_message)

        except Exception:
            break


# =========================
# START RECEIVE THREAD
# =========================

receive_thread = threading.Thread(target=receive_messages)
receive_thread.daemon = True
receive_thread.start()


# =========================
# SEND MESSAGE
# =========================

while True:
    message = input("Enter message ('exit' to quit): ")

    encrypted_message = encrypt_message(aes_key, message)
    client_socket.send(encrypted_message)

    if message == "exit":
        break


client_socket.close()