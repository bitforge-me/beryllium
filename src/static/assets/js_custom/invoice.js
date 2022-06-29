/* global io */

const bolt11 = document.currentScript.getAttribute('data-bolt11');
const label = document.currentScript.getAttribute('data-label');

function socketOpen(label) {
    const socket = io('/events', {transports: ['websocket']});
    console.log('socket.io protocol:', socket.protocol);
    socket.on('connect', function() {
        console.log('connected');
        // subscribe to invoice events
        if (label.length > 0) {
            socket.emit('ln_invoice', label, (response) => console.log(`sent invoice label: ${label}`));
        }
    });
    socket.on('info', function(msg) {
        console.log(`info: ${msg}`);
    });
    socket.on('version', function(msg) {
        console.log(`version: ${msg}`);
    });
    socket.on('ln_invoice_paid', function(msg) {
        console.log('invoice paid:', msg);
        msg = JSON.parse(msg);
        const bolt11 = msg.bolt11;
        console.log(bolt11);
        const shortenedBolt11 = bolt11.slice(0, 15) + '.....' + bolt11.slice(-15);
        bootbox.alert({
            title: 'Invoice Paid',
            message: shortenedBolt11
        });
    });
}

function confirm(formclass, amount) {
    if (!document.querySelector(formclass).reportValidity()) {
        return;
    }
    if (isNaN(amount) || amount <= 0) {
        bootbox.alert({message: 'Invalid amount'});
        return;
    }
    bootbox.confirm({
        message: `Are you sure you want to create an invoice for ${amount} sats?`,
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
    socketOpen(label);

    $('#copy-invoice').click(function() {
        navigator.clipboard.writeText(bolt11);
    });

    $('#form-submit').click(function() {
        const amount = $('#amount').val();
        confirm('#form', amount);
        return false;
    });
});
