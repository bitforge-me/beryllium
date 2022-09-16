const largestChannelSats = parseFloat(document.currentScript.getAttribute('data-largest-channel-sats'));
const channels = JSON.parse(document.currentScript.getAttribute('data-channels'));
const totalSpendableSats = parseFloat(document.currentScript.getAttribute('data-total-spendable-sats'));
const totalReceivableSats = parseFloat(document.currentScript.getAttribute('data-total-receivable-sats'));

function confirmClose(form, channelShortId) {
    bootbox.confirm({
        title: 'Confirm Close Channel',
        message: `Do you want to close the channel ${channelShortId}?`,
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
                form.submit();
            }
        }
    });
}

function confirmRebalance(formclass, oscid, iscid, amount) {
    if (!document.querySelector(formclass).reportValidity()) {
        return;
    }
    if (isNaN(amount) || amount <= 0) {
        bootbox.alert({message: 'Invalid amount'});
        return;
    }
    bootbox.confirm({
        title: 'Confirm Rebalance Channels',
        message: `Moving ${amount} sats from ${oscid} to ${iscid}. Do you want to continue?`,
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
    $('.close-channel-submit').click(function() {
        const channelShortId = $(this).prev().val();
        const form = $(this).parent();
        confirmClose(form, channelShortId);
        return false;
    });

    $('#rebalance-channel-submit').click(function() {
        const oscid = $('#oscid').val();
        const iscid = $('#iscid').val();
        const amount = $('#amount').val();
        confirmRebalance('#rebalance-channel-form', oscid, iscid, amount);
        return false;
    });

    // set progress bar widths
    const totalLiquidity = totalSpendableSats + totalReceivableSats;
    const spendableWidth = totalSpendableSats / totalLiquidity * 100;
    const receivableWidth = totalReceivableSats / totalLiquidity * 100;
    document.getElementById('progbar-total-spendable').style = `width: ${spendableWidth}%`;
    document.getElementById('progbar-total-receivable').style = `width: ${receivableWidth}%`;
    channels.forEach(channel => {
        const ratio = channel.total_sats / largestChannelSats;
        document.getElementById(`progbar-${channel.short_channel_id}-our-reserve`).style = `width: ${channel.our_reserve_sats / channel.total_sats * 100 * ratio}%;`;
        document.getElementById(`progbar-${channel.short_channel_id}-spendable`).style = `width: ${channel.spendable_sats / channel.total_sats * 100 * ratio}%;`;
        document.getElementById(`progbar-${channel.short_channel_id}-receivable`).style = `width: ${channel.receivable_sats / channel.total_sats * 100 * ratio}%;`;
        document.getElementById(`progbar-${channel.short_channel_id}-their-reserve`).style = `width: ${channel.their_reserve_sats / channel.total_sats * 100 * ratio}%;`;
    });
});
