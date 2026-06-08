from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import socket
import threading


# =========================
# SERVER CONFIG
# =========================

HOST = "localhost"
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"Server is running on {HOST}:{PORT}")


# =========================
# GENERATE SERVER RSA KEY
# =========================

server_key = RSA.generate(2048)


# =========================
# LIST CONNECTED CLIENTS
# =========================

clients = []


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
# HANDLE CLIENT
# =========================

def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    try:
        # Gửi public key của server cho client
        server_public_key = server_key.publickey().export_key(format="PEM")
        client_socket.send(server_public_key)

        # Nhận public key của client
        client_public_key_data = client_socket.recv(2048)
        client_received_key = RSA.import_key(client_public_key_data)

        # Tạo AES key để mã hóa tin nhắn
        aes_key = get_random_bytes(16)

        # Mã hóa AES key bằng public key của client
        cipher_rsa = PKCS1_OAEP.new(client_received_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Gửi AES key đã mã hóa cho client
        client_socket.send(encrypted_aes_key)

        # Thêm client vào danh sách
        clients.append((client_socket, aes_key))

        while True:
            encrypted_message = client_socket.recv(4096)

            if not encrypted_message:
                break

            decrypted_message = decrypt_message(aes_key, encrypted_message)

            print(f"Received from {client_address}: {decrypted_message}")

            # Gửi tin nhắn đến các client khác
            for client, key in clients:
                if client != client_socket:
                    encrypted = encrypt_message(key, decrypted_message)
                    client.send(encrypted)

            if decrypted_message == "exit":
                break

    except Exception as e:
        print(f"Error with {client_address}: {e}")

    finally:
        if (client_socket, aes_key) in clients:
            clients.remove((client_socket, aes_key))

        client_socket.close()
        print(f"Connection with {client_address} closed")


# =========================
# ACCEPT CLIENT CONNECTIONS
# =========================

while True:
    client_socket, client_address = server_socket.accept()

    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address)
    )

    client_thread.start()