function confirm(csrfToken, delayBefore, delayAfter, coordLock) {
    bootbox.confirm({
        message: `Are you sure you want to run the test with request delay before of '${delayBefore}', request delay after of '${delayAfter}' and coordination lock of '${coordLock}'?`,
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
                const token1 = Math.random().toString(36).slice(2, 7);
                const token2 = Math.random().toString(36).slice(2, 7);
                const resDiv = $('#result');
                resDiv.html(`requesting, token1: <span class="token">${token1}</span>, token2: <span class="token">${token2}</span>...`);
                const params = {csrf_token: csrfToken, read_delay_before: delayBefore, read_delay_after: delayAfter, coordlock: coordLock, action: 'write', value: token1};
                $.post('/db_test_action', params, function(data, textStatus) {
                    console.log(data);
                    console.log(textStatus);
                    resDiv.html(`${resDiv.html()}<br/>wrote <span class="token">${token1}</span>: ${data}<br/>reading...`);
                    params.action = 'read';
                    $.post('/db_test_action', params, function(data, textStatus) {
                        console.log(data);
                        console.log(textStatus);
                        resDiv.html(`${resDiv.html()}<br/>read: <span class="token">${data}</span><br/>Finished.`);
                    });
                    setTimeout(function() {
                        params.action = 'write';
                        params.value = token2;
                        $.post('/db_test_action', params, function(data, textStatus) {
                            console.log(data);
                            console.log(textStatus);
                            resDiv.html(`${resDiv.html()}<br/>wrote <span class="token">${token2}</span>: ${data}`);
                        });
                    }, (delayBefore + delayAfter / 2) * 1000);
                });
            }
        }
    });
}

$(document).ready(function() {
    $('#form-submit').click(function() {
        const csrfToken = $('#csrfToken').val();
        const delayBefore = $('#delayBefore').val();
        const delayAfter = $('#delayAfter').val();
        const coordLock = $('#coordLock').prop('checked');
        confirm(csrfToken, delayBefore, delayAfter, coordLock);
        return false;
    });
});
