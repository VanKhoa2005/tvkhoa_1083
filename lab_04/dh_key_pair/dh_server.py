"""
Server Socket - Diffie-Hellman + AES Chat
Mỗi client thực hiện trao đổi khóa DH riêng với server
Sau đó dùng shared secret dẫn xuất khóa AES-128 để mã hóa tin nhắn
"""

import socket
import threading
import os
import hashlib

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Tạo DH parameters chung (2048-bit)
print("[SERVER] Đang tạo tham số Diffie-Hellman 2048-bit...")
DH_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)
print("[SERVER] Tham số DH đã sẵn sàng.")

clients = []       # Danh sách (socket, aes_key, address)
clients_lock = threading.Lock()


def derive_aes_key(shared_secret: bytes) -> bytes:
    """Dẫn xuất khóa AES-128 từ shared secret DH bằng SHA-256."""
    return hashlib.sha256(shared_secret).digest()[:16]


def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    """Mã hóa AES-128-CBC, trả về IV + ciphertext."""
    iv = os.urandom(16)
    padded = _pkcs7_pad(plaintext.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return iv + ciphertext


def aes_decrypt(key: bytes, data: bytes) -> str:
    """Giải mã AES-128-CBC từ IV + ciphertext."""
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded).decode('utf-8')


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


def broadcast(message: str, exclude_socket=None):
    """Gửi tin nhắn AES-mã hóa tới tất cả client (trừ người gửi)."""
    with clients_lock:
        dead = []
        for (sock, aes_key, addr) in clients:
            if sock == exclude_socket:
                continue
            try:
                encrypted = aes_encrypt(aes_key, message)
                length = len(encrypted).to_bytes(4, 'big')
                sock.sendall(length + encrypted)
            except Exception:
                dead.append((sock, aes_key, addr))
        for d in dead:
            clients.remove(d)


def recv_exact(sock, n):
    """Đọc đúng n bytes từ socket."""
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối bị đóng")
        buf += chunk
    return buf


def handle_client(client_socket, client_address):
    aes_key = None
    try:
        print(f"[SERVER] Client kết nối: {client_address}")

        # 1. Gửi DH parameters (PEM) cho client
        params_pem = DH_PARAMETERS.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
        param_len = len(params_pem).to_bytes(4, 'big')
        client_socket.sendall(param_len + params_pem)

        # 2. Server tạo cặp khóa DH riêng cho client này
        server_private_key = DH_PARAMETERS.generate_private_key()
        server_public_key  = server_private_key.public_key()
        server_pub_pem = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # 3. Gửi khóa công khai DH của server
        spub_len = len(server_pub_pem).to_bytes(4, 'big')
        client_socket.sendall(spub_len + server_pub_pem)

        # 4. Nhận khóa công khai DH của client
        cpub_len = int.from_bytes(recv_exact(client_socket, 4), 'big')
        client_pub_pem = recv_exact(client_socket, cpub_len)
        client_public_key = serialization.load_pem_public_key(client_pub_pem)

        # 5. Tính shared secret -> dẫn xuất khóa AES-128
        shared_secret = server_private_key.exchange(client_public_key)
        aes_key = derive_aes_key(shared_secret)
        print(f"[SERVER] Khóa AES-128 đã thoả thuận với {client_address}: {aes_key.hex()}")

        # 6. Gửi ACK xác nhận bắt tay hoàn tất
        ack = aes_encrypt(aes_key, "HANDSHAKE_OK")
        ack_len = len(ack).to_bytes(4, 'big')
        client_socket.sendall(ack_len + ack)

        # 7. Nhận tên người dùng từ client
        name_len = int.from_bytes(recv_exact(client_socket, 4), 'big')
        name_data = recv_exact(client_socket, name_len)
        username = aes_decrypt(aes_key, name_data)
        print(f"[SERVER] Người dùng '{username}' đã tham gia.")

        # Thêm vào danh sách clients
        with clients_lock:
            clients.append((client_socket, aes_key, client_address))

        # Thông báo tham gia tới tất cả
        broadcast(f"[HỆ THỐNG]: {username} đã tham gia phòng chat.", exclude_socket=client_socket)

        # 8. Vòng lặp nhận và phát tin nhắn
        while True:
            try:
                msg_len = int.from_bytes(recv_exact(client_socket, 4), 'big')
                msg_data = recv_exact(client_socket, msg_len)
                plaintext = aes_decrypt(aes_key, msg_data)
                print(f"[SERVER] Từ '{username}': {plaintext}")

                if plaintext.strip().lower() == "exit":
                    break

                # Phát tới các client khác
                broadcast(f"{username}: {plaintext}", exclude_socket=client_socket)
            except ConnectionError:
                break
            except Exception as e:
                print(f"[SERVER] Lỗi xử lý tin nhắn từ {client_address}: {e}")
                break

    except Exception as e:
        print(f"[SERVER] Lỗi bắt tay với {client_address}: {e}")
    finally:
        if aes_key is not None:
            with clients_lock:
                clients[:] = [(s, k, a) for (s, k, a) in clients if s != client_socket]
        client_socket.close()
        print(f"[SERVER] Đã đóng kết nối: {client_address}")
        broadcast(f"[HỆ THỐNG]: Một người dùng đã rời phòng chat.")


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 12346))
    server_socket.listen(10)
    print("[SERVER] Đang lắng nghe trên cổng 12346 (Diffie-Hellman + AES Chat)...")

    while True:
        try:
            client_sock, client_addr = server_socket.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
            t.start()
        except Exception as e:
            print(f"[SERVER] Lỗi chấp nhận kết nối: {e}")


if __name__ == '__main__':
    main()
