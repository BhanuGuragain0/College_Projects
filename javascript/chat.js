const form = document.querySelector(".typing-area"),
    incoming_id = form.querySelector(".incoming_id").value,
    inputField = form.querySelector(".input-field"),
    sendBtn = form.querySelector("button"),
    chatBox = document.querySelector(".chat-box");

let lastMessageId = 0;
let isLoading = false;

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
        .then(response => response.text())
        .then((data) => {
            inputField.value = "";
            sendBtn.classList.remove("active");
            scrollToBottom();
            // Fetch messages immediately after sending
            fetchMessages();
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

function fetchMessages() {
    if (isLoading) return;

    isLoading = true;

    fetch("php/get-chat.php?incoming_id=" + incoming_id, {
        method: "GET"
    })
        .then(response => response.text())
        .then(data => {
            chatBox.innerHTML = data;
            if (!chatBox.classList.contains("active")) {
                scrollToBottom();
            }
            isLoading = false;
        })
        .catch(error => {
            console.error("Error fetching messages:", error);
            isLoading = false;
        });
}

// Fetch messages every 2 seconds (optimized from 500ms - 75% reduction in requests)
setInterval(fetchMessages, 2000);

// Initial fetch
fetchMessages();

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

