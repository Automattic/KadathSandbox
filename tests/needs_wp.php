<?php
// e2e fixture: a file lifted out of a plugin. As a bare webshell it dies on
// add_action(); adopted as a plugin (--adopt-wp) WordPress is loaded beneath it,
// the hook fires on the next request, and the option lands in the DB diff. The value
// is unique per request: the engine does not reset options between offerings, so a
// constant value would be a no-op update on every run after the first.
add_action('init', function () {
    update_option('kadath_adopted_probe', 'fired-' . microtime(true));
});
