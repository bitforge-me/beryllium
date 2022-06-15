function confirm(formclass, amount, nodeid) {
    if (!document.querySelector(formclass).reportValidity()) {
        return;
    }
    bootbox.confirm({
        title: 'Opening Channel',
        message: `Confirm the creation of channel ${nodeid} with the amount of ${amount} sats`,
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
        const nodeid = $('#nodeid').val();
        confirm('#form', amount, nodeid);
        return false;
    });
});
