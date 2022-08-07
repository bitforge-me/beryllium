const interstitial = JSON.parse(document.currentScript.getAttribute('data-interstitial'));
const completed = JSON.parse(document.currentScript.getAttribute('data-completed'));
const cancelled = JSON.parse(document.currentScript.getAttribute('data-cancelled'));
const windcaveUrl = document.currentScript.getAttribute('data-windcave-url');

$(document).ready(function() {
    if (!interstitial) {
        if (!completed && !cancelled) {
            if (windcaveUrl !== null && windcaveUrl !== '') {
                window.location.replace(windcaveUrl);
            }
        }
    }

    $('#close').click(function() {
        // 'window.close()' will not work unless JS created the window
        // so we do it this way to allow us to close this window
        open(location, '_self').close();
        return false;
    });
});
