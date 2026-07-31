<?php

/*
|--------------------------------------------------------------------------
| Register Namespaces And Routes
|--------------------------------------------------------------------------
|
| When a module starting, this file will executed automatically. This helps
| to register some namespaces like translator or view. Also this file
| will load the routes file for each module. You may also modify
| this file as you want.
|
*/

// str_starts_with() polyfill for PHP < 8.0 (used by the bundled WebAuthn library).
require_once __DIR__ . '/Vendor/polyfill.php';

// PSR-4 autoloader for the bundled lbuchs/WebAuthn library. The library is
// vendored unmodified under its upstream namespace, which is outside the
// module's own Modules\Passkeys\ autoload root.
spl_autoload_register(function ($class) {
    $prefix = 'lbuchs\\WebAuthn\\';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $file = __DIR__ . '/Vendor/WebAuthn/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';

    if (file_exists($file)) {
        require $file;
    }
});

if (!app()->routesAreCached()) {
    require __DIR__ . '/Http/routes.php';
}
