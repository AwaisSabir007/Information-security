(() => {
  const container = document.getElementById("message-list");
  const form = document.getElementById("message-form");
  const input = document.getElementById("chat-input");
  if (!container || !form || !window.chatConfig) {
    return;
  }

  let lastCount = 0;

  const attachBtn = document.getElementById("attach-btn");
  const fileInput = document.getElementById("image-upload");

  function buildMessageBubble(msg) {
    const isSelf = msg.sender === window.chatConfig.currentUser;
    const wrapper = document.createElement("div");
    wrapper.className = `flex w-full items-end gap-3 ${isSelf ? "justify-end text-right" : "justify-start"}`;

    const avatar = document.createElement("div");
    avatar.className = "bg-primary/10 text-primary rounded-full w-10 h-10 shrink-0 flex items-center justify-center font-heading uppercase";
    avatar.textContent = msg.sender.slice(0, 2);

    const textWrapper = document.createElement("div");
    textWrapper.className = `flex flex-col gap-1 max-w-2xl ${isSelf ? "items-end" : "items-start"}`;

    // Helper to render content
    let contentElement;
    if (msg.content.startsWith("[IMAGE]:")) {
      const base64Data = msg.content.substring(8); // Remove prefix
      contentElement = document.createElement("img");
      contentElement.src = base64Data;
      contentElement.className = "rounded-lg shadow-md max-w-xs border border-gray-200 dark:border-gray-700 cursor-pointer hover:opacity-90 transition";
      contentElement.onclick = () => {
        const win = window.open();
        win.document.write(`<img src="${base64Data}" style="max-width:100%">`);
      };
    } else {
      contentElement = document.createElement("p");
      contentElement.className = `text-base leading-relaxed rounded-3xl px-4 py-3 shadow-sm max-w-full ${isSelf ? "rounded-br-none bg-primary text-white" : "rounded-bl-none bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
        }`;
      contentElement.textContent = msg.content;
    }

    const timestamp = document.createElement("p");
    timestamp.className = "text-gray-500 dark:text-gray-400 text-xs";
    timestamp.textContent = new Date(msg.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

    if (isSelf) {
      textWrapper.appendChild(contentElement);
      textWrapper.appendChild(timestamp);
      wrapper.appendChild(textWrapper);
      wrapper.appendChild(avatar);
    } else {
      textWrapper.appendChild(contentElement);
      textWrapper.appendChild(timestamp);
      wrapper.appendChild(avatar);
      wrapper.appendChild(textWrapper);
    }

    return wrapper;
  }

  // ... (buildDateSeparator logic) ...

  function buildDateSeparator(date) {
    const separator = document.createElement("div");
    separator.className = "flex items-center justify-center my-4";
    const pill = document.createElement("span");
    pill.className = "px-3 py-1 text-xs text-gray-500 dark:text-gray-400 bg-white/80 dark:bg-gray-800/60 rounded-full shadow";
    pill.textContent = date;
    separator.appendChild(pill);
    return separator;
  }

  async function fetchMessages() {
    const response = await fetch(`/get_messages/${encodeURIComponent(window.chatConfig.receiver)}`);
    if (!response.ok) return;
    const messages = await response.json();
    if (messages.length === lastCount) return;
    lastCount = messages.length;
    container.innerHTML = "";
    if (messages.length === 0) {
      const empty = document.createElement("div");
      empty.className = "text-center text-gray-500 dark:text-gray-400";
      empty.textContent = "No messages yet. Say hello securely!";
      container.appendChild(empty);
    } else {
      let lastDate = null;
      messages.forEach((msg) => {
        const msgDate = new Date(msg.timestamp);
        const dateLabel = msgDate.toLocaleDateString(undefined, {
          weekday: "short",
          month: "short",
          day: "numeric",
        });
        if (dateLabel !== lastDate) {
          container.appendChild(buildDateSeparator(dateLabel));
          lastDate = dateLabel;
        }
        container.appendChild(buildMessageBubble(msg));
      });
    }
    container.scrollTop = container.scrollHeight;
  }

  async function sendMessage(evt) {
    evt.preventDefault();
    const data = new FormData(form);

    const payload = {
      receiver: data.get("receiver"),
      message: data.get("message")
    };

    // If file is selected (logichandled via separate listener, but if we wanted to merge...)
    // Actually, let's keep text sending simple here.

    const response = await fetch("/send_message", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    if (response.ok) {
      form.reset();
      if (input) {
        input.focus();
      }
      fetchMessages();
    }
  }

  // Handle File Attachment
  if (attachBtn && fileInput) {
    attachBtn.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", () => {
      const file = fileInput.files[0];
      if (!file) return;

      if (file.size > 2 * 1024 * 1024) {
        alert("File too large. Max 2MB.");
        fileInput.value = "";
        return;
      }

      const reader = new FileReader();
      reader.onload = async (e) => {
        const base64Data = e.target.result;
        const payload = {
          receiver: window.chatConfig.receiver,
          message: `[IMAGE]:${base64Data}`
        };

        const response = await fetch("/send_message", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });

        if (response.ok) {
          fileInput.value = ""; // Reset
          fetchMessages();
        } else {
          alert("Failed to send image.");
        }
      };
      reader.readAsDataURL(file);
    });
  }

  form.addEventListener("submit", sendMessage);
  fetchMessages();
  setInterval(fetchMessages, window.chatConfig.pollInterval * 1000);
})();

