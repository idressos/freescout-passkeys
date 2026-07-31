<?php
/**
 * Minimal polyfill so the bundled lbuchs/WebAuthn library (which uses
 * str_starts_with) runs on every PHP version supported by FreeScout (7.1+).
 * On PHP 8.0+ the native implementation is used.
 */

if (!function_exists('str_starts_with')) {
    /**
     * @param string $haystack
     * @param string $needle
     * @return bool
     */
    function str_starts_with($haystack, $needle)
    {
        return $needle === '' || strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
