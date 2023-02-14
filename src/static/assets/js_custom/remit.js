function confirmCreate(formClass, payname, name, acct, amount, currency) {
    bootbox.confirm({
        message: `Are you sure you want to create an invoice for ${amount} ${currency} to ${name} - ${acct} at ${payname}?`,
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

function confirmStatus(formClass, refId) {
    bootbox.confirm({
        message: `Are you sure you want to get the status for ${refId}?`,
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

function confirmRefund(formClass, refId, bolt11) {
    bootbox.confirm({
        message: `Are you sure you want to refund ${refId} to ${bolt11}?`,
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
    $('#refId-group').hide();
    $('#paycode-group').hide();
    $('#name-group').hide();
    $('#acct-group').hide();
    $('#mobile-group').hide();
    $('#currency-group').hide();
    $('#amount-group').hide();
    $('#desc-group').hide();
    $('#bolt11-group').hide();
    $('select[name=action] option:selected').each(function() {
        const value = $(this).val();
        if (value === 'create') {
            $('#paycode-group').show();
            $('#name-group').show();
            $('select[name=paycode] option:selected').each(function() {
                const value = $(this).attr('x-cat');
                if (value === 'bank') {
                    $('#acct-group').show();
                }
                if (value === 'mobileMoney') {
                    $('#mobile-group').show();
                }
            });
            $('#currency-group').show();
            $('#amount-group').show();
            $('#desc-group').show();
        }
        if (value === 'status') {
            $('#refId-group').show();
        }
        if (value === 'refund') {
            $('#refId-group').show();
            $('#bolt11-group').show();
        }
    });
}

$(document).ready(function() {
    updateForm();

    $('select[name=action]').change(function() {
        updateForm();
    });
    $('select[name=paycode]').change(function() {
        updateForm();
    });

    $('#form-submit').click(function() {
        const action = $('#action').val();
        const refId = $('#refId').val();
        const payname = $('#paycode option:selected').text();
        const name = $('#name').val();
        let acct = $('#acct').val();
        const cat = $('select[name=paycode] option:selected').first().attr('x-cat');
        if (cat === 'mobileMoney') {
            acct = $('#mobile').val();
        }
        const currency = $('#currency').val();
        const amount = $('#amount').val();
        const bolt11 = $('#bolt11').val();
        if (action === 'create') {
            confirmCreate('#form', payname, name, acct, amount, currency);
        }
        if (action === 'status') {
            confirmStatus('#form', refId);
        }
        if (action === 'refund') {
            confirmRefund('#form', refId, bolt11);
        }
        return false;
    });
});
