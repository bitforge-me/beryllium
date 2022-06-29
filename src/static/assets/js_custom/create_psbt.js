const psbt = document.currentScript.getAttribute('data-psbt');
const onchain = document.currentScript.getAttribute('data-onchain');
const onchainSats = document.currentScript.getAttribute('data-onchain-sats');
const addrs = JSON.parse(document.currentScript.getAttribute('data-addrs'));
const amounts = JSON.parse(document.currentScript.getAttribute('data-amounts'));

function confirm(formclass, outputs, totalBtc, action, unit) {
    if (!document.querySelector(formclass).reportValidity()) {
        return;
    }
    if (isNaN(totalBtc) || totalBtc <= 0) {
        bootbox.alert({message: 'Invalid amount'});
        return;
    }
    bootbox.confirm({
        title: `Confirm Create ${action}`,
        message: `Total: ${totalBtc}${unit}. Do you want to create the ${action}?`,
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

function addOutput(addr, amount) {
    document.querySelector('.payment-fields').insertAdjacentHTML('afterend',
        `
    <div class="payment-fields">
        <hr>
        <div class="form-group">
            <label for="address" class="form-label">Recipient Address</label>
            <input type="text" id="address" name="address" class="payment form-control" placeholder="Recipient Address" value="${addr}" required>
        </div>
        <div class="form-group">
            <label for="amount" class="form-label">Amount</label>
            <input type="text" id="amount" name="amount" class="payment form-control" placeholder="Amount" value="${amount}" required>
        </div>
    </div>
`);
    $('#form-remove-output').show();
}

$(document).ready(function() {
    $('#copy-psbt').click(function() {
        navigator.clipboard.writeText(psbt);
    });

    $('#max').click(function() {
        const ele = $('#max').parent().prev();
        console.log(ele);
        const unit = document.querySelector('input[name="unit"]:checked').value;
        if (unit === 'btc') {
            return ele.val(onchain);
        } else if (unit === 'sat') {
            return ele.val(onchainSats);
        }
    });

    $('#form-remove-output').hide();
    $('#form-remove-output').click(function() {
        const ele = $('.payment-fields').last();
        console.log(ele);
        ele.remove();
        if ($('.payment-fields').length === 1) {
            $('#form-remove-output').hide();
        }
        return false;
    });

    $('#form-add-output').click(function() {
        addOutput('', '');
        return false;
    });

    $('#form-submit').click(function() {
        const outputs = [];
        const paymentFields = document.getElementsByClassName('payment');
        let totalBtc = 0;
        for (let i = 0; i < paymentFields.length; i += 2) {
            const output = {sats: paymentFields[i].value, btc: paymentFields[i + 1].value};
            outputs.push(output);
            totalBtc += parseFloat(output.btc);
        }
        totalBtc = Math.round(totalBtc * 100000000) / 100000000;
        const mode = document.querySelector('input[name="mode"]:checked').value;
        const unit = document.querySelector('input[name="unit"]:checked').value;
        let action = '!ERR!';
        if (mode === 'psbt') {
            action = 'PSBT';
        } else if (mode === 'withdraw') {
            action = 'Withdrawal Transaction';
        } else {
            return;
        }
        confirm('#form', outputs, totalBtc, action, unit);
        return false;
    });

    // load initial values
    for (let i = 0; i < addrs.length; i++) {
        if (i === 0) {
            $('#address').val(addrs[i]);
            $('#amount').val(amounts[i]);
        } else {
            addOutput(addrs[i], amounts[i]);
        }
    }
});
