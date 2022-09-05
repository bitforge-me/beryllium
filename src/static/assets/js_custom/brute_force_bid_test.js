function confirm(formclass, market, quoteAssetAmount) {
    bootbox.confirm({
        message: `Are you sure you want to bid in '${market}', with a quote asset amount of '${quoteAssetAmount}'?`,
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
        const market = $('#market').val();
        const quoteAssetAmount = $('#quoteAssetAmount').val();
        confirm('#form', market, quoteAssetAmount);
        return false;
    });
});
