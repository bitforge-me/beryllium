/*global decodePsbt, formatOutputs*/

const signedPsbt = document.currentScript.getAttribute('data-signed-psbt');

async function confirm(formClass, psbt) {
    if (!document.querySelector(formClass).reportValidity()) {
        return;
    }
    const data = await decodePsbt(psbt);
    if (data == null) {
        return;
    }
    let message = 'Do you want to sign?<br/>';
    message = message + formatOutputs(data.fee, data.outputs);
    bootbox.confirm({
        title: 'Confirm Sign',
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
                $(formClass).submit();
            }
        }
    });
}

$(document).ready(function() {
    $('#copy-psbt').click(function() {
        navigator.clipboard.writeText(signedPsbt);
    });

    $('#form-submit').click(function() {
        const psbt = $('#psbt').val();
        confirm('#form', psbt);
        return false;
    });
});
