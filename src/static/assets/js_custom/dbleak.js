
document.addEventListener('DOMContentLoaded', function() {
    const submit = document.getElementById('submit');
    submit.addEventListener('click', function() {
        const div = document.getElementById('here');
        const img = document.createElement('img');
        img.src = 'static/assets/img/index_img/bid.jpg';
        img.width = 100;
        img.height = 100;
        div.appendChild(img);
    });
});
