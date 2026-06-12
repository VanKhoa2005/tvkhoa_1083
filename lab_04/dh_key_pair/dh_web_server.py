"""
Flask Web Server - Diffie-Hellman + AES Socket Chat
Kết nối với dh_server.py (cổng 12346)
"""

import socket
import threading
import queue
import json
import os
import hashlib
from flask import Flask, render_template, request, jsonify, Response

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# ---------- Session store ----------
sessions = {}
sessions_lock = threading.Lock()

DH_SERVER_HOST = 'localhost'
DH_SERVER_PORT = 12346


# ---------- Crypto helpers ----------
def derive_aes_key(shared_secret: bytes) -> bytes:
    return hashlib.sha256(shared_secret).digest()[:16]


def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    iv = os.urandom(16)
    padded = _pkcs7_pad(plaintext.encode('utf-8'))
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def aes_decrypt(key: bytes, data: bytes) -> str:
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    return _pkcs7_unpad(padded).decode('utf-8')


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    return data[:-data[-1]]


def recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối bị đóng")
        buf += chunk
    return buf


def send_msg(sock, aes_key, text):
    """Mã hóa và gửi tin nhắn có length-prefix."""
    enc = aes_encrypt(aes_key, text)
    sock.sendall(len(enc).to_bytes(4, 'big') + enc)


def sse(event, data):
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


# ---------- Background reader ----------
def socket_reader(client_id, sock, aes_key, q):
    while True:
        try:
            msg_len = int.from_bytes(recv_exact(sock, 4), 'big')
            msg_data = recv_exact(sock, msg_len)
            plaintext = aes_decrypt(aes_key, msg_data)

            if ':' in plaintext:
                sender, text = plaintext.split(':', 1)
                q.put({'type': 'message', 'sender': sender.strip(), 'text': text.strip()})
            else:
                q.put({'type': 'status', 'message': plaintext})
        except Exception:
            with sessions_lock:
                active = client_id in sessions and sessions[client_id].get('active')
            if active:
                q.put({'type': 'status', 'message': 'Kết nối tới server đã đóng.'})
            break


# ---------- Cleanup ----------
def cleanup(client_id):
    with sessions_lock:
        s = sessions.pop(client_id, None)
    if s:
        s['active'] = False
        try:
            s['socket'].close()
        except Exception:
            pass


# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('dh_index.html')


@app.route('/stream')
def stream():
    username  = request.args.get('username', '').strip()
    client_id = request.args.get('client_id', '').strip()
    if not username or not client_id:
        return 'Thiếu thông tin', 400

    def generate():
        q = queue.Queue()
        session = {'active': True, 'socket': None, 'aes_key': None, 'queue': q, 'done': False}
        with sessions_lock:
            sessions[client_id] = session

        try:
            # Bước 1: Kết nối TCP
            yield sse('status', {'msg': 'Đang kết nối tới máy chủ DH...', 'progress': 10})
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((DH_SERVER_HOST, DH_SERVER_PORT))
            session['socket'] = sock

            # Bước 2: Nhận DH parameters
            yield sse('status', {'msg': 'Đang nhận tham số Diffie-Hellman...', 'progress': 25})
            param_len = int.from_bytes(recv_exact(sock, 4), 'big')
            params_pem = recv_exact(sock, param_len)
            from cryptography.hazmat.primitives.asymmetric.dh import DHParameters
            from cryptography.hazmat.primitives.serialization import load_pem_parameters
            dh_params = load_pem_parameters(params_pem)

            # Bước 3: Tạo cặp khóa DH của client
            yield sse('status', {'msg': 'Đang tạo cặp khóa Diffie-Hellman...', 'progress': 40})
            client_private = dh_params.generate_private_key()
            client_public  = client_private.public_key()

            # Bước 4: Nhận khóa công khai DH của server
            yield sse('status', {'msg': 'Đang trao đổi khóa công khai DH với server...', 'progress': 55})
            spub_len = int.from_bytes(recv_exact(sock, 4), 'big')
            server_pub_pem = recv_exact(sock, spub_len)
            server_pub_key = serialization.load_pem_public_key(server_pub_pem)

            # Bước 5: Gửi khóa công khai DH của client
            client_pub_pem = client_public.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(len(client_pub_pem).to_bytes(4, 'big') + client_pub_pem)

            # Bước 6: Tính shared secret -> AES key
            yield sse('status', {'msg': 'Đang tính Shared Secret và dẫn xuất khóa AES-128...', 'progress': 70})
            shared_secret = client_private.exchange(server_pub_key)
            aes_key = derive_aes_key(shared_secret)
            session['aes_key'] = aes_key

            # Bước 7: Nhận ACK xác nhận
            ack_len = int.from_bytes(recv_exact(sock, 4), 'big')
            ack_data = recv_exact(sock, ack_len)
            ack_text = aes_decrypt(aes_key, ack_data)
            if ack_text != 'HANDSHAKE_OK':
                yield sse('error', {'message': 'Bắt tay DH thất bại!'})
                return

            # Bước 8: Gửi tên người dùng
            yield sse('status', {'msg': 'Đang xác nhận danh tính người dùng...', 'progress': 85})
            send_msg(sock, aes_key, username)

            # Hoàn thành
            yield sse('ready', {
                'msg': 'Kết nối bảo mật thành công! Kênh chat đã sẵn sàng.',
                'progress': 100,
                'aes_key': aes_key.hex()
            })
            session['done'] = True

            # Khởi chạy luồng đọc tin nhắn nền
            t = threading.Thread(target=socket_reader, args=(client_id, sock, aes_key, q), daemon=True)
            t.start()

            # Phát sự kiện từ queue
            while session['active']:
                try:
                    event = q.get(timeout=1.5)
                    yield sse(event['type'], event)
                except queue.Empty:
                    yield sse('ping', {})

        except Exception as e:
            yield sse('error', {'message': f'Lỗi: {str(e)}'})
        finally:
            cleanup(client_id)

    return Response(generate(), mimetype='text/event-stream')


@app.route('/send', methods=['POST'])
def send():
    data = request.json or {}
    client_id = data.get('client_id')
    message   = data.get('message', '').strip()
    if not client_id or not message:
        return jsonify({'ok': False, 'error': 'Thiếu thông tin'}), 400

    with sessions_lock:
        session = sessions.get(client_id)
    if not session or not session.get('done'):
        return jsonify({'ok': False, 'error': 'Chưa kết nối'}), 400

    try:
        send_msg(session['socket'], session['aes_key'], message)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/disconnect', methods=['POST'])
def disconnect():
    data = request.json or {}
    cid = data.get('client_id')
    if cid:
        cleanup(cid)
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
