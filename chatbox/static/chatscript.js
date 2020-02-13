send_socket = new WebSocket('ws://0.0.0.0:8000/sendsocket');
textbox = document.getElementById('message');

// Ask if there are new messages
function ask_update() {
    let message = {
        type: 'update'
    }
    send_socket.send(JSON.stringify(message));
}

// Send a message
function send_message() {
    let message = {
        type: 'msg',
        msg: textbox.value
    }
    send_socket.send(JSON.stringify(message));
    textbox.value = '';
}

// Process received messages
send_socket.onmessage = function (event) {
    let data = JSON.parse(event.data);
    if (data.length === 0) return;
    for (let i = 0; i < data.length; i++) {
        let new_message = `
            <div id="messages">
            <div class="media-body">
            <h4>${data[i].sender} <small><i>Posted on ${data[i].posted}</i></small></h4>
            <p>${data[i].message}</p>
            </div>`;
            document.getElementById("messages").innerHTML += new_message

    }
    window.scrollTo(0, document.body.scrollHeight);
}

// Register message listener
setInterval(ask_update, 500)