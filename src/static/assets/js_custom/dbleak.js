
$(document).ready(function() {
    $('#submit').click(function() {
        const div = document.getElementById('here');
        div.innerHTML += `<img src="static/assets/img/index_img/bid.jpg"
        width="100"
        height="100"
        alt="bid logo"/>`;
    });
});
