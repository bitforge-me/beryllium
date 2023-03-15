function confirm(formClass, subject, recipient) {
    bootbox.confirm({
        message: `Are you sure you want to send email with "${subject}" to recipient "${recipient}"?`,
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
        const subject = $('#subject').val();
        const recipient = $('#recipient').val();
        confirm('#form', subject, recipient);
        return false;
    });
});
