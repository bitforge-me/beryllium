/* exported decodePsbt */
/* exported formatOutputs */

async function decodePsbt(psbt) {
    const response = await fetch('decode_psbt?' + new URLSearchParams({psbt}));
    if (!response.ok) {
        bootbox.alert({message: `An error has occured decoding the psbt: ${response.status}`});
        return null;
    }
    const data = await response.json();

    const fee = data.fee;
    const outputs = [];
    for (let i = 0; i < data.tx.vout.length; i++) {
        const vout = data.tx.vout[i];
        const addr = vout.scriptPubKey.address;
        const output = [addr, vout.value];
        outputs.push(output);
    }
    return {fee, outputs};
}

function formatOutputs(fee, outputs) {
    let html = '<ul>';
    for (let i = 0; i < outputs.length; i++) {
        const output = outputs[i];
        html = html + `<li>Address: ${output[0]}, Amount: ${output[1]} BTC</li>`;
    }
    html = html + `<li>Fee Amount: ${fee} BTC</li>`;
    return html;
}
