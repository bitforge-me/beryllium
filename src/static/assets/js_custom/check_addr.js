function confirm(formClass) {
    bootbox.confirm({
        message: 'Are you sure you want check the address?',
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
        confirm('#form');
        return false;
    });
});
