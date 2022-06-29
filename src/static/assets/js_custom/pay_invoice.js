async function decodeInvoice(invoice) {
    const response = await fetch(`decode_bolt11/${invoice}`);
    if (!response.ok) {
        bootbox.alert({message: `An error has occured decoding the invoice: ${response.status}`});
        return null;
    }
    const data = await response.json();
    return data;
}

async function confirm(formclass, amount) {
    if (!document.querySelector(formclass).reportValidity()) {
        return;
    }
    const invoice = document.querySelector('#invoice').value;
    const data = await decodeInvoice(invoice);
    if (data == null) {
        return;
    }

    bootbox.confirm({
        message: `Are you sure you want to pay the invoice? - Amount: ${data.amount_sat} sats, Description: ${data.description}`,
        buttons: {
            confirm: {
                label: 'Yes',
                className: 'btn-success'
            },
            cancel: {
                label: 'No',
                className: 'btn-danger'
            }
        },
        callback: function(result) {
            if (result) {
                $(formclass).submit();
            }
        }
    });
}

$(document).ready(function() {
    $('#form-submit').click(function() {
        const amount = $('#amount').val();
        confirm('#form', amount);
        return false;
    });
});
