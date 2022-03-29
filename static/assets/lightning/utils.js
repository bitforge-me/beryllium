async function decodePsbt(psbt) {
    const response = await fetch('decode_psbt?' + new URLSearchParams({psbt: psbt}));
    if (!response.ok) {
        bootbox.alert({message: `An error has occured decoding the psbt: ${response.status}`});
        return null;
    }
    const data = await response.json();
    
    const fee = data.fee;
    var outputs = [];
    for (var i = 0; i < data.tx.vout.length; i++) {
        const vout = data.tx.vout[i];
        const addr = vout.scriptPubKey.address;
        var output = [addr, vout.value];
        outputs.push(output);
    }
    return {'fee': fee, 'outputs': outputs};
}

function formatOutputs(fee, outputs) {
    var html = '<ul>';
    for (var i = 0; i < outputs.length; i++) {
        const output = outputs[i];
        html = html + `<li>Address: ${output[0]}, Amount: ${output[1]} BTC</li>`;
    }
    html = html + `<li>Fee Amount: ${fee} BTC</li>`;
    return html;
}