let formId = null;

$('.submit_button').click(function() {
    formId = null;
    formId = this.getAttribute('data-form');
    const action = this.getAttribute('data-action');
    $('#submit_action').text(action);
});

$('#submit').click(function() {
    $('#' + formId).submit();
});
