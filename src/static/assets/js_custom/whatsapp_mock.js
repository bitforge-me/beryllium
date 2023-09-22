async function decodeInvoice(invoice) {
    const response = await fetch(`decode_bolt11/${invoice}`);
    if (!response.ok) {
        bootbox.alert({message: `An error has occured decoding the invoice: ${response.status}`});
        return null;
    }
    const data = await response.json();
    return data;
}

function showMessage(message, colorClass='text-muted', faClass='fa-caret-right') {
    message = message.replaceAll('<', '&lt;')
    message = message.replaceAll('>', '&gt;')
    message = message.replaceAll('\n', `<br><i class="px-1 fas ${faClass} invisible"></i>`)
    const output = $('#output');
    output.append(`<div class="${colorClass}"><i class="px-1 fas ${faClass}"></i>${message}</div>`)
    output.scrollTop(output.prop('scrollHeight'));
}

function showError(message) {
    showMessage(message, 'text-danger', 'fa-exclamation-circle');    
}

function showResponse(message) {
    showMessage(message, 'text-muted', 'fa-caret-left');    
}

async function sendMessage() {
    const tel = $('#tel').val();
    const input = $('#input').val();

    if (tel == '') {
        return;
    }

    if (input == '') {
        return;
    }

    showMessage(input)
    $('#input').val('');

    const body = new FormData();
    body.append('tel', tel);
    body.append('input', input);
    console.log(body);
    const response = await fetch('send_msg',
        {
            method: 'post',
            body: body
        }
    );
    if (!response.ok) {
        showError('error sending message');
    } else {
        const data = await response.text();
        showResponse(data);
    }
}

$(document).ready(function() {
    $('#form-submit').click(function() {
        sendMessage();
        return false;
    });
});
