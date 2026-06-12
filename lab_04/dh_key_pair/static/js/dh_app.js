// Biến phiên
let clientId = '';
let username = '';
let eventSource = null;

// DOM
const loginScreen       = document.getElementById('login-screen');
const chatScreen        = document.getElementById('chat-screen');
const connectForm       = document.getElementById('connect-form');
const usernameInput     = document.getElementById('username-input');
const btnConnect        = document.getElementById('btn-connect');
const connectError      = document.getElementById('connect-error');
const connectingStatus  = document.getElementById('connecting-status');
const connectingText    = document.getElementById('connecting-text');
const progressWrap      = document.getElementById('progress-wrap');
const progressBar       = document.getElementById('progress-bar');

const headerStatus      = document.getElementById('header-status');
const statusText        = document.getElementById('status-text');
const headerUsername    = document.getElementById('header-username');

const messagesArea      = document.getElementById('messages-area');
const chatForm          = document.getElementById('chat-form');
const messageInput      = document.getElementById('message-input');
const btnSend           = document.getElementById('btn-send');
const btnDisconnect     = document.getElementById('btn-disconnect');

function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
        const r = Math.random() * 16 | 0;
        return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
    });
}

function getTime() {
    return new Date().toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
}

function addMessage(sender, text, isOutgoing) {
    const group = document.createElement('div');
    group.className = `msg-group ${isOutgoing ? 'outgoing' : 'incoming'}`;
    if (!isOutgoing) {
        const s = document.createElement('div');
        s.className = 'msg-sender';
        s.textContent = sender;
        group.appendChild(s);
    }
    const b = document.createElement('div');
    b.className = 'msg-bubble';
    b.textContent = text;
    group.appendChild(b);
    const t = document.createElement('div');
    t.className = 'msg-time';
    t.textContent = getTime();
    group.appendChild(t);
    messagesArea.appendChild(group);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function addSysMsg(text) {
    const el = document.createElement('div');
    el.className = 'sys-msg';
    el.textContent = text;
    messagesArea.appendChild(el);
    messagesArea.scrollTop = messagesArea.scrollHeight;
}

function resetUI() {
    loginScreen.classList.remove('hidden');
    chatScreen.classList.add('hidden');
    connectingStatus.classList.add('hidden');
    progressWrap.classList.add('hidden');
    connectError.classList.add('hidden');
    btnConnect.disabled = false;
    usernameInput.disabled = false;
    btnConnect.textContent = 'Bắt đầu trò chuyện →';
    messageInput.disabled = true;
    btnSend.disabled = true;
    messageInput.value = '';
    if (eventSource) { eventSource.close(); eventSource = null; }
}

// Kết nối
connectForm.addEventListener('submit', e => {
    e.preventDefault();
    username = usernameInput.value.trim();
    if (!username) return;

    clientId = generateUUID();
    btnConnect.disabled = true;
    usernameInput.disabled = true;
    connectError.classList.add('hidden');
    connectingStatus.classList.remove('hidden');
    progressWrap.classList.remove('hidden');
    connectingText.textContent = 'Đang kết nối tới máy chủ DH...';

    const url = `/stream?username=${encodeURIComponent(username)}&client_id=${encodeURIComponent(clientId)}`;
    eventSource = new EventSource(url);

    // Cập nhật tiến trình bắt tay DH
    eventSource.addEventListener('status', e => {
        const d = JSON.parse(e.data);
        connectingText.textContent = d.msg;
        if (d.progress) progressBar.style.width = d.progress + '%';
    });

    // Bắt tay hoàn tất → vào phòng chat
    eventSource.addEventListener('ready', e => {
        const d = JSON.parse(e.data);
        connectingText.textContent = d.msg;
        progressBar.style.width = '100%';

        setTimeout(() => {
            loginScreen.classList.add('hidden');
            chatScreen.classList.remove('hidden');
            headerUsername.textContent = username;
            headerStatus.className = 'header-status connected';
            statusText.textContent = 'Đã kết nối – DH + AES-128-CBC';
            messageInput.disabled = false;
            btnSend.disabled = false;
            messageInput.focus();
            addSysMsg(`Chào mừng ${username}! Khóa AES đã thoả thuận qua Diffie-Hellman.`);
        }, 500);
    });

    // Nhận tin nhắn
    eventSource.addEventListener('message', e => {
        const d = JSON.parse(e.data);
        addMessage(d.sender, d.text, false);
    });

    // Thông báo hệ thống trong chat
    eventSource.addEventListener('status_chat', e => {
        const d = JSON.parse(e.data);
        addSysMsg(d.message);
    });

    // Lỗi
    eventSource.addEventListener('error', e => {
        let msg = 'Không thể kết nối. Hãy kiểm tra dh_server.py đang chạy trên cổng 12346.';
        try { msg = JSON.parse(e.data).message || msg; } catch (_) {}
        connectingStatus.classList.add('hidden');
        progressWrap.classList.add('hidden');
        connectError.textContent = msg;
        connectError.classList.remove('hidden');
        btnConnect.disabled = false;
        usernameInput.disabled = false;
        if (eventSource) { eventSource.close(); eventSource = null; }
    });
});

// Gửi tin nhắn
chatForm.addEventListener('submit', e => {
    e.preventDefault();
    const text = messageInput.value.trim();
    if (!text) return;
    messageInput.value = '';

    fetch('/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId, message: text })
    })
    .then(r => r.json())
    .then(d => {
        if (d.ok) {
            addMessage(username, text, true);
        } else {
            addSysMsg(`Lỗi gửi: ${d.error}`);
        }
    })
    .catch(() => addSysMsg('Lỗi kết nối khi gửi tin nhắn.'));
});

// Ngắt kết nối
btnDisconnect.addEventListener('click', () => {
    fetch('/disconnect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: clientId })
    }).finally(resetUI);
});

window.addEventListener('beforeunload', () => {
    if (clientId) navigator.sendBeacon('/disconnect', JSON.stringify({ client_id: clientId }));
});
