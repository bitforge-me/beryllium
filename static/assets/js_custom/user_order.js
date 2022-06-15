function confirm(formClass, action, token) {
    bootbox.confirm({
        message: `Are you sure you want to ${action} for order ${token}?`,
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
    $('#form-submit').click(function() {
        const action = $('#action').val();
        const token = $('#token').val();
        confirm('#form', action, token);
        return false;
    });
});
