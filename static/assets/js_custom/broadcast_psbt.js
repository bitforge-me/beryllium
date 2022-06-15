/* globals decodePsbt, formatOutputs */

async function confirm(formclass, signedPsbt) {
    if (!document.querySelector(formclass).reportValidity()) {
        return;
    }
    const data = await decodePsbt(signedPsbt);
    if (data == null) {
        return;
    }
    let message = 'Do you want to broadcast?<br/>';
    message = message + formatOutputs(data.fee, data.outputs);
    bootbox.confirm({
        title: 'Confirm Broadcast',
        message,
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
        const signedPsbt = $('#psbt').val();
        confirm('#form', signedPsbt);
        return false;
    });
});
