const form = document.querySelector(".typing-area"),
    incoming_id = form.querySelector(".incoming_id").value,
    inputField = form.querySelector(".input-field"),
    sendBtn = form.querySelector("button"),
    chatBox = document.querySelector(".chat-box");

let lastMessageId = 0;
let eventSource = null;
let isConnected = false;

form.onsubmit = (e) => {
    e.preventDefault();
};

inputField.focus();
inputField.onkeyup = () => {
    if (inputField.value !== "") {
        sendBtn.classList.add("active");
    } else {
        sendBtn.classList.remove("active");
    }
};

sendBtn.onclick = () => {
    if (inputField.value.trim() === "") {
        return;
    }

    let formData = new FormData(form);

    fetch("php/insert-chat.php", {
        method: "POST",
        body: formData
    })
        .then(response => response.json())
        .then((data) => {
            if (data.status === 'success') {
                inputField.value = "";
                sendBtn.classList.remove("active");
                scrollToBottom();
            } else {
                showNotification(data.message || "Failed to send message", "error");
            }
        })
        .catch(error => {
            console.error("Error sending message:", error);
            showNotification("Failed to send message", "error");
        });
};

chatBox.onmouseenter = () => {
    chatBox.classList.add("active");
};

chatBox.onmouseleave = () => {
    chatBox.classList.remove("active");
};

// SSE Implementation for Real-time Chat
function initSSE() {
    if (eventSource) {
        eventSource.close();
    }

    eventSource = new EventSource(`php/get-chat.php?incoming_id=${incoming_id}&last_msg_id=${lastMessageId}`);

    eventSource.addEventListener('connected', (e) => {
        console.log('SSE Connected:', JSON.parse(e.data));
        isConnected = true;
    });

    eventSource.addEventListener('message', (e) => {
        const data = JSON.parse(e.data);
        if (data.messages && data.messages.length > 0) {
            appendMessages(data.messages);
            lastMessageId = Math.max(...data.messages.map(m => m.msg_id));
            if (!chatBox.classList.contains("active")) {
                scrollToBottom();
            }
        }
    });

    eventSource.addEventListener('heartbeat', (e) => {
        console.log('Heartbeat received');
    });

    eventSource.onerror = (error) => {
        console.error('SSE Error:', error);
        isConnected = false;
        // Reconnect after 3 seconds
        setTimeout(() => {
            if (!isConnected) {
                console.log('Attempting to reconnect SSE...');
                initSSE();
            }
        }, 3000);
    };

    eventSource.onopen = () => {
        console.log('SSE Connection opened');
        isConnected = true;
    };
}

function appendMessages(messages) {
    messages.forEach(message => {
        const isOutgoing = message.outgoing_msg_id == document.querySelector('.outgoing_id')?.value;
        const messageHTML = createMessageHTML(message, isOutgoing);
        chatBox.insertAdjacentHTML('beforeend', messageHTML);
    });
}

function createMessageHTML(message, isOutgoing) {
    const img = message.sender_img || 'default.png';
    const name = `${message.sender_fname || ''} ${message.sender_lname || ''}`.trim();
    
    if (isOutgoing) {
        return `<div class="chat outgoing">
                    <div class="details">
                        <p>${escapeHtml(message.msg)}</p>
                        <span class="time">${formatTime(message.created_at)}</span>
                    </div>
                </div>`;
    } else {
        return `<div class="chat incoming">
                    <img src="php/images/${img}" alt="${name}">
                    <div class="details">
                        <p>${escapeHtml(message.msg)}</p>
                        <span class="time">${formatTime(message.created_at)}</span>
                    </div>
                </div>`;
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatTime(timestamp) {
    if (!timestamp) return 'now';
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function scrollToBottom() {
    chatBox.scrollTop = chatBox.scrollHeight;
}

function showNotification(message, type = "info") {
    const notification = document.createElement("div");
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.classList.add("show");
    }, 100);

    setTimeout(() => {
        notification.classList.remove("show");
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Initialize SSE on page load
document.addEventListener('DOMContentLoaded', () => {
    initSSE();
    scrollToBottom();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (eventSource) {
        eventSource.close();
    }
});

