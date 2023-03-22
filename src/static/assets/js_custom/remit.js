function confirmStatus(formClass, token) {
    bootbox.confirm({
        message: `Are you sure you want to get the status for ${token}?`,
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

function confirmRefund(formClass, token) {
    bootbox.confirm({
        message: `Are you sure you want to refund ${token}?`,
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

function updateForm() {
    // hide all optional elements
    $('#token-group').hide();
    $('select[name=action] option:selected').each(function() {
        const value = $(this).val();
        if (value === 'status') {
            $('#token-group').show();
        }
        if (value === 'refund') {
            $('#token-group').show();
        }
    });
}

$(document).ready(function() {
    updateForm();

    $('select[name=action]').change(function() {
        updateForm();
    });

    $('#form-submit').click(function() {
        const action = $('#action').val();
        const token = $('#token').val();
        if (action === 'status') {
            confirmStatus('#form', token);
        }
        if (action === 'refund') {
            confirmRefund('#form', token);
        }
        return false;
    });
});
