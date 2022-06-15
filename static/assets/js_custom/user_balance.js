function confirm(formClass, action, email, asset, amount) {
    bootbox.confirm({
        message: `Are you sure you want to ${action} ${amount} ${asset} for ${email}?`,
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
    $('#asset-group').hide();
    $('#amount-group').hide();
    $('#desc-group').hide();
    $('select[name=action] option:selected').each(function() {
        const value = $(this).val();
        if (value === 'credit' || value === 'debit') {
            $('#asset-group').show();
            $('#amount-group').show();
            $('#desc-group').show();
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
        const email = $('#email').val();
        let asset = '';
        if ($('#asset-group:visible').length > 0) {
            asset = $('#asset').val();
        }
        let amount = '';
        if ($('#amount-group:visible').length > 0) {
            amount = $('#amount').val();
        }
        confirm('#form', action, email, asset, amount);
        return false;
    });
});
