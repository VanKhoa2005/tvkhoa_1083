import socket
import threading
import queue
import json
import time
from flask import Flask, render_template, request, jsonify, Response
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

# Global sessions storage
sessions = {}
sessions_lock = threading.Lock()

def sse_event(event_type, data):
    """Formats an SSE message."""
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

def socket_reader(client_id, sock, aes_key, msg_queue):
    """Background thread to read and decrypt messages from the socket server."""
    while True:
        try:
            # Buffer size 2048 to accommodate ciphertext overhead
            encrypted_message = sock.recv(2048)
            if not encrypted_message:
                msg_queue.put({"type": "status", "message": "Kết nối đã bị đóng bởi socket server."})
                break
            
            # Decrypt the AES-128-CBC message
            iv = encrypted_message[:AES.block_size]
            ciphertext = encrypted_message[AES.block_size:]
            
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_bytes = cipher.decrypt(ciphertext)
            decrypted_message = unpad(decrypted_bytes, AES.block_size).decode('utf-8')
            
            # Parse sender if message format is "Sender: message"
            if ":" in decrypted_message:
                parts = decrypted_message.split(":", 1)
                sender = parts[0].strip()
                message_text = parts[1].strip()
            else:
                sender = "Server/Phát thanh"
                message_text = decrypted_message
                
            msg_queue.put({
                "type": "message",
                "sender": sender,
                "text": message_text,
                "crypto": {
                    "iv": iv.hex(),
                    "ciphertext": ciphertext.hex(),
                    "algorithm": "AES-128-CBC (Chế độ CBC, Khối 16-byte)"
                }
            })
        except Exception as e:
            # When socket is closed in cleanup, recv will throw an exception
            # We exit the loop silently if session is no longer active
            with sessions_lock:
                session_active = client_id in sessions and sessions[client_id]['active']
            if session_active:
                msg_queue.put({"type": "status", "message": f"Lỗi đọc socket: {str(e)}"})
            break

def cleanup_session(client_id):
    """Closes socket and removes session data."""
    with sessions_lock:
        if client_id in sessions:
            session_data = sessions[client_id]
            session_data['active'] = False
            sock = session_data['socket']
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
            del sessions[client_id]

@app.route('/')
def index():
    """Renders the main secure chat dashboard."""
    return render_template('index.html')

@app.route('/stream')
def stream():
    """Server-Sent Events stream for secure chat state changes and messages."""
    username = request.args.get('username')
    client_id = request.args.get('client_id')
    
    if not username or not client_id:
        return "Thiếu tên người dùng hoặc ID client", 400

    def event_generator():
        q = queue.Queue()
        session_data = {
            'username': username,
            'client_id': client_id,
            'socket': None,
            'aes_key': None,
            'rsa_key': None,
            'server_pub': None,
            'queue': q,
            'active': True,
            'handshake_done': False,
            'reader_thread': None
        }
        
        with sessions_lock:
            sessions[client_id] = session_data

        try:
            # Step 1: RSA Key Generation
            yield sse_event("handshake", {"status": "Đang tạo cặp khóa RSA-2048 cho Client...", "progress": 20})
            client_key = RSA.generate(2048)
            session_data['rsa_key'] = client_key
            
            client_pub_pem = client_key.publickey().export_key(format='PEM').decode('utf-8')
            client_priv_pem = client_key.export_key(format='PEM').decode('utf-8')
            yield sse_event("keys", {
                "client_pub": client_pub_pem,
                "client_priv": client_priv_pem
            })

            # Step 2: Establish socket connection
            yield sse_event("handshake", {"status": "Đang kết nối tới Socket Server (localhost:12345)...", "progress": 40})
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(('localhost', 12345))
            except Exception as e:
                yield sse_event("error", {
                    "message": f"Không thể kết nối đến TCP server: {str(e)}. Vui lòng kiểm tra xem server.py có đang chạy trên cổng 12345 không!"
                })
                sock.close()
                return
            
            session_data['socket'] = sock

            # Step 3: Key Exchange - Receive Server's Public Key
            yield sse_event("handshake", {"status": "Trao đổi khóa công khai: Đang nhận khóa công khai của Server...", "progress": 60})
            server_pub_raw = sock.recv(2048)
            if not server_pub_raw:
                yield sse_event("error", {"message": "Server đã đóng kết nối trong quá trình trao đổi khóa."})
                return
            
            server_public_key = RSA.import_key(server_pub_raw)
            session_data['server_pub'] = server_public_key
            yield sse_event("server_pub", {
                "server_pub": server_public_key.export_key(format='PEM').decode('utf-8')
            })

            # Step 4: Key Exchange - Send Client's Public Key
            yield sse_event("handshake", {"status": "Trao đổi khóa công khai: Đang gửi khóa công khai của Client...", "progress": 75})
            sock.send(client_key.publickey().export_key(format='PEM'))

            # Step 5: Receive and decrypt the AES key
            yield sse_event("handshake", {"status": "Đang chờ nhận khóa phiên AES đã mã hóa từ Server...", "progress": 85})
            encrypted_aes_key = sock.recv(2048)
            if not encrypted_aes_key:
                yield sse_event("error", {"message": "Server đã đóng kết nối khi đang gửi khóa phiên."})
                return
            
            yield sse_event("encrypted_aes_key", {"encrypted_aes_hex": encrypted_aes_key.hex()})

            yield sse_event("handshake", {"status": "Đang giải mã khóa AES bằng khóa bí mật RSA của Client...", "progress": 95})
            
            cipher_rsa = PKCS1_OAEP.new(client_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            session_data['aes_key'] = aes_key
            
            yield sse_event("aes_key", {"aes_key_hex": aes_key.hex()})
            yield sse_event("handshake", {"status": "Thiết lập thành công khóa đối xứng AES-128! Kênh truyền bảo mật đã hoạt động.", "progress": 100})
            
            session_data['handshake_done'] = True

            # Start reading messages in a background thread
            reader_thread = threading.Thread(target=socket_reader, args=(client_id, sock, aes_key, q))
            reader_thread.daemon = True
            session_data['reader_thread'] = reader_thread
            reader_thread.start()

            # Wait for items in the queue and yield them to the front-end
            while session_data['active']:
                try:
                    event = q.get(timeout=1.5)
                    yield sse_event(event['type'], event)
                except queue.Empty:
                    # Send a keep-alive ping
                    yield sse_event("ping", {})
        except Exception as e:
            yield sse_event("error", {"message": f"Bắt tay/Phiên kết nối thất bại: {str(e)}"})
        finally:
            cleanup_session(client_id)

    return Response(event_generator(), mimetype='text/event-stream')

@app.route('/send', methods=['POST'])
def send_message():
    """Receives message from client UI, encrypts it, and forwards it to TCP socket server."""
    data = request.json
    client_id = data.get('client_id')
    message = data.get('message')

    if not client_id or message is None:
        return jsonify({"success": False, "error": "Thiếu ID client hoặc tin nhắn"}), 400

    with sessions_lock:
        session_data = sessions.get(client_id)

    if not session_data or not session_data['handshake_done']:
        return jsonify({"success": False, "error": "Chưa hoàn tất bắt tay mật mã hoặc phiên đã đóng"}), 400

    try:
        sock = session_data['socket']
        aes_key = session_data['aes_key']
        username = session_data['username']

        # Format message as "Username: message" so recipients know who sent it
        formatted_message = f"{username}: {message}"
        
        # Encrypt with AES-CBC
        cipher = AES.new(aes_key, AES.MODE_CBC)
        padded_data = pad(formatted_message.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        
        # Structure is IV + ciphertext
        payload = cipher.iv + ciphertext
        
        # Send to socket server
        sock.send(payload)

        # Return the cryptographic details so the sender's UI can visualize the operation
        return jsonify({
            "success": True,
            "crypto": {
                "plaintext": formatted_message,
                "iv": cipher.iv.hex(),
                "ciphertext": ciphertext.hex(),
                "algorithm": "AES-128-CBC (Chế độ CBC, Khối 16-byte)"
            }
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Gửi thất bại: {str(e)}"}), 500

@app.route('/disconnect', methods=['POST'])
def disconnect():
    """Disconnects the client socket cleanly."""
    data = request.json
    client_id = data.get('client_id')
    if client_id:
        cleanup_session(client_id)
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Thiếu ID client"}), 400

if __name__ == '__main__':
    # Run server on port 5000
    app.run(debug=True, host='0.0.0.0', port=5000)
