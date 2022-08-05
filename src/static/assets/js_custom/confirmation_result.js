$(document).ready(function() {
    $('#close').click(function() {
        // 'window.close()' will not work unless JS created the window
        // so we do it this way to allow us to close this window
        open(location, '_self').close();
        return false;
    });
});
