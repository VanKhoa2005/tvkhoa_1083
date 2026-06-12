// Biến toàn cục
let clientId = '';
let username = '';
let eventSource = null;
let rawAesKeyHex = '';
let aesKeyVisible = false;

// Phần tử DOM
const connectionScreen = document.getElementById('connection-screen');
const chatDashboard = document.getElementById('chat-dashboard');
const connectForm = document.getElementById('connect-form');
const usernameInput = document.getElementById('username-input');
const btnConnect = document.getElementById('btn-connect');
const connectError = document.getElementById('connect-error');

const connectionIndicator = document.getElementById('connection-indicator');
const connectionStatusText = document.getElementById('connection-status-text');

const cryptoLogs = document.getElementById('crypto-logs');
const progressBar = document.getElementById('handshake-progress-bar');
const progressNum = document.getElementById('handshake-progress-num');

const clientPubKey = document.getElementById('client-public-key');
const clientPrivKey = document.getElementById('client-private-key');
const serverPubKey = document.getElementById('server-public-key');
const aesSessionKey = document.getElementById('aes-session-key');
const btnToggleAes = document.getElementById('btn-toggle-aes');

const chatMessages = document.getElementById('chat-messages');
const chatForm = document.getElementById('chat-form');
const messageInput = document.getElementById('message-input');
const btnSend = document.getElementById('btn-send');
const btnDisconnect = document.getElementById('btn-disconnect');

const encryptionPreview = document.getElementById('encryption-preview');
const previewLength = document.getElementById('preview-length');
const previewPad = document.getElementById('preview-pad');
const previewBlocks = document.getElementById('preview-blocks');

// Tạo mã UUID ngẫu nhiên cho phiên Client
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Khôi phục giao diện về trạng thái ngắt kết nối
function resetUI() {
    connectionScreen.classList.remove('hidden');
    chatDashboard.classList.add('hidden');
    
    connectionIndicator.className = 'indicator disconnected';
    connectionStatusText.textContent = 'Đã ngắt kết nối';
    
    // Khôi phục nút kết nối
    btnConnect.disabled = false;
    usernameInput.disabled = false;
    btnConnect.querySelector('span').textContent = 'THIẾT LẬP KẾT NỐI BẢO MẬT';
    
    // Xóa bảng điều khiển mật mã
    cryptoLogs.innerHTML = '<div class="log-entry system">Đang chờ khởi tạo kết nối bảo mật...</div>';
    progressBar.style.width = '0%';
    progressNum.textContent = '0%';
    
    // Xóa thư mục khóa
    clientPubKey.textContent = 'Đang tạo...';
    clientPrivKey.textContent = 'Đang tạo...';
    serverPubKey.textContent = 'Đang chờ trao đổi...';
    aesSessionKey.textContent = 'Đang chờ bắt tay bảo mật...';
    btnToggleAes.classList.add('hidden');
    rawAesKeyHex = '';
    
    // Xóa hộp chat
    messageInput.value = '';
    messageInput.disabled = true;
    btnSend.disabled = true;
    
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}

// Định dạng thời gian
function getTimestamp() {
    const now = new Date();
    return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// Thêm Log vào Console Bắt tay
function appendLog(type, message) {
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${getTimestamp()}] ${message}`;
    cryptoLogs.appendChild(entry);
    cryptoLogs.scrollTop = cryptoLogs.scrollHeight;
}

// Thu gọn/Mở rộng accordion của Khóa bảo mật
window.toggleAccordion = function(id) {
    const container = document.getElementById(id);
    const section = container.parentElement;
    
    if (container.classList.contains('hidden')) {
        container.classList.remove('hidden');
        section.classList.add('active');
        // Kích hoạt hiệu ứng chuyển động
        setTimeout(() => {
            container.style.maxHeight = container.scrollHeight + "px";
        }, 10);
    } else {
        container.style.maxHeight = "0px";
        section.classList.remove('active');
        setTimeout(() => {
            container.classList.add('hidden');
        }, 300);
    }
};

// Ẩn/Hiện khóa đối xứng AES dưới dạng plain text
window.toggleAESVisibility = function() {
    aesKeyVisible = !aesKeyVisible;
    if (aesKeyVisible) {
        aesSessionKey.textContent = rawAesKeyHex;
        btnToggleAes.textContent = '👁️‍🗨️';
    } else {
        aesSessionKey.textContent = '•'.repeat(rawAesKeyHex.length);
        btnToggleAes.textContent = '👁';
    }
};

// Tính toán các thông số đệm PKCS7 trực tiếp khi gõ
messageInput.addEventListener('input', (e) => {
    const text = e.target.value;
    
    // Server sẽ đính kèm thêm tiền tố "Tên: " trước khi gửi qua socket
    const fullMessage = `${username}: ${text}`;
    
    // Lấy kích thước byte của chuỗi định dạng UTF-8
    const byteLength = new TextEncoder().encode(fullMessage).length;
    
    // Kích thước khối AES là 16 bytes
    const padBytes = 16 - (byteLength % 16);
    const blocks = Math.ceil((byteLength + padBytes) / 16);
    
    previewLength.textContent = byteLength;
    previewPad.textContent = padBytes;
    previewBlocks.textContent = blocks;
});

// Thêm tin nhắn chat vào bảng hiển thị
function appendChatMessage(sender, text, isOutgoing, crypto = null) {
    const wrapper = document.createElement('div');
    wrapper.className = `message-wrapper ${isOutgoing ? 'outgoing' : 'incoming'}`;
    
    // Tên người gửi
    const senderTag = document.createElement('div');
    senderTag.className = 'message-sender';
    senderTag.textContent = sender;
    wrapper.appendChild(senderTag);
    
    // Bong bóng tin nhắn
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    bubble.textContent = text;
    
    // Thời gian gửi
    const timeTag = document.createElement('div');
    timeTag.className = 'message-time';
    timeTag.textContent = getTimestamp();
    bubble.appendChild(timeTag);
    
    // Chi tiết mật mã học tích hợp (Thu gọn)
    if (crypto) {
        const cryptoDiv = document.createElement('div');
        cryptoDiv.className = 'message-crypto-details hidden';
        
        cryptoDiv.innerHTML = `
            <div class="crypto-title">
                <span>Thông tin mật mã AES</span>
                <span>${crypto.algorithm}</span>
            </div>
            <div>
                <span class="lbl">Vector khởi tạo (IV):</span>
                <span class="val">${crypto.iv}</span>
            </div>
            <div>
                <span class="lbl">Bản mã (Ciphertext):</span>
                <span class="val">${crypto.ciphertext}</span>
            </div>
        `;
        
        wrapper.appendChild(bubble);
        wrapper.appendChild(cryptoDiv);
        
        // Sự kiện click bong bóng chat để bật/tắt chi tiết mật mã
        bubble.addEventListener('click', () => {
            cryptoDiv.classList.toggle('hidden');
            chatMessages.scrollTop = chatMessages.scrollHeight;
        });
    } else {
        wrapper.appendChild(bubble);
    }
    
    chatMessages.appendChild(wrapper);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Thêm thông báo hệ thống vào bảng chat
function appendSystemMessage(text) {
    const div = document.createElement('div');
    div.className = 'system-message';
    div.innerHTML = `<span class="sys-badge">HỆ THỐNG</span>${text}`;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Thiết lập kết nối bảo mật qua EventSource (SSE)
connectForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    username = usernameInput.value.trim();
    if (!username) return;
    
    clientId = generateUUID();
    
    // Vô hiệu hóa nút và input khi đang kết nối
    btnConnect.disabled = true;
    usernameInput.disabled = true;
    btnConnect.querySelector('span').textContent = 'ĐANG KẾT NỐI TỚI SOCKET...';
    connectError.classList.add('hidden');
    
    connectionIndicator.className = 'indicator connecting';
    connectionStatusText.textContent = 'Đang bắt tay mật mã...';
    
    // Khởi tạo kênh SSE
    const url = `/stream?username=${encodeURIComponent(username)}&client_id=${encodeURIComponent(clientId)}`;
    eventSource = new EventSource(url);
    
    // Hiển thị bảng điều khiển chat chính
    connectionScreen.classList.add('hidden');
    chatDashboard.classList.remove('hidden');
    
    // Lắng nghe sự kiện bắt tay mật mã
    eventSource.addEventListener('handshake', (event) => {
        const data = JSON.parse(event.data);
        appendLog('info', data.status);
        
        progressBar.style.width = `${data.progress}%`;
        progressNum.textContent = `${data.progress}%`;
        
        if (data.progress === 100) {
            appendLog('success', 'Bắt tay hoàn tất. Kênh truyền dẫn đã được mã hóa toàn vẹn.');
        }
    });
    
    // Lắng nghe sự kiện tạo cặp khóa RSA cục bộ
    eventSource.addEventListener('keys', (event) => {
        const data = JSON.parse(event.data);
        clientPubKey.textContent = data.client_pub;
        clientPrivKey.textContent = data.client_priv;
        appendLog('success', 'Đã khởi tạo cặp khóa RSA-2048 thành công trên Client.');
    });
    
    // Lắng nghe sự kiện nhận khóa công khai của Server
    eventSource.addEventListener('server_pub', (event) => {
        const data = JSON.parse(event.data);
        serverPubKey.textContent = data.server_pub;
        appendLog('success', 'Đã trao đổi và lưu khóa công khai RSA của Server.');
    });
    
    // Lắng nghe sự kiện nhận khóa AES đã mã hóa
    eventSource.addEventListener('encrypted_aes_key', (event) => {
        const data = JSON.parse(event.data);
        appendLog('info', `Đã nhận khóa AES mã hóa (RSA-Cipher): ${data.encrypted_aes_hex.substring(0, 32)}...`);
    });
    
    // Kênh bảo mật kích hoạt sau khi giải mã khóa đối xứng AES
    eventSource.addEventListener('aes_key', (event) => {
        const data = JSON.parse(event.data);
        rawAesKeyHex = data.aes_key_hex;
        
        // Ẩn nội dung khóa AES ban đầu
        aesSessionKey.textContent = '•'.repeat(rawAesKeyHex.length);
        btnToggleAes.classList.remove('hidden');
        
        // Cập nhật thẻ trạng thái bảo mật
        connectionIndicator.className = 'indicator connected';
        connectionStatusText.textContent = 'Bảo mật bằng AES-128-CBC';
        appendSystemMessage(`Kênh truyền bảo mật đã thiết lập. Định danh của bạn: "${username}"`);
        
        // Kích hoạt các trường nhập tin nhắn
        messageInput.disabled = false;
        btnSend.disabled = false;
        messageInput.focus();
    });
    
    // Nhận tin nhắn chat của các client khác đã được giải mã
    eventSource.addEventListener('message', (event) => {
        const data = JSON.parse(event.data);
        appendChatMessage(data.sender, data.text, false, data.crypto);
    });
    
    // Nhận thông điệp trạng thái từ máy chủ
    eventSource.addEventListener('status', (event) => {
        const data = JSON.parse(event.data);
        appendSystemMessage(data.message);
    });
    
    // Nhận thông báo lỗi phiên
    eventSource.addEventListener('error', (event) => {
        let msg = 'Kênh kết nối SSE gặp sự cố.';
        if (event.data) {
            try {
                const data = JSON.parse(event.data);
                msg = data.message || msg;
            } catch(e) {}
        }
        
        appendLog('error', msg);
        appendSystemMessage(`Lỗi hệ thống: ${msg}`);
        
        // Đưa người dùng về màn hình portal đăng nhập sau 1.5s
        setTimeout(() => {
            resetUI();
            connectError.textContent = msg;
            connectError.classList.remove('hidden');
        }, 1500);
    });
});

// Gửi tin nhắn bảo mật
chatForm.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const message = messageInput.value.trim();
    if (!message) return;
    
    messageInput.value = '';
    
    // Đặt lại số liệu trên thanh phân tích mã hóa
    previewLength.textContent = '0';
    previewPad.textContent = '16';
    previewBlocks.textContent = '1';
    
    fetch('/send', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            client_id: clientId,
            message: message
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            // Hiển thị tin nhắn của chính mình vừa gửi lên màn hình kèm chi tiết mã hóa
            appendChatMessage(username, message, true, data.crypto);
        } else {
            appendSystemMessage(`Gửi tin nhắn thất bại: ${data.error}`);
        }
    })
    .catch(err => {
        appendSystemMessage(`Lỗi truyền dẫn: ${err}`);
    });
});

// Xử lý nút bấm Ngắt kết nối
btnDisconnect.addEventListener('click', () => {
    if (confirm('Bạn có chắc chắn muốn ngắt kết nối và đóng kênh truyền bảo mật không?')) {
        appendLog('info', 'Đang ngắt kết nối kênh truyền bảo mật...');
        
        fetch('/disconnect', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                client_id: clientId
            })
        })
        .finally(() => {
            resetUI();
        });
    }
});

// Ngắt kết nối tự động khi tắt tab hoặc tắt trình duyệt
window.addEventListener('beforeunload', () => {
    if (clientId) {
        navigator.sendBeacon('/disconnect', JSON.stringify({ client_id: clientId }));
    }
});
