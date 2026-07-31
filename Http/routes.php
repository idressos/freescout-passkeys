<?php

// Passkey management - authenticated users manage their own passkeys only.
// 'throttle' caps abuse of the registration verification endpoint (which
// parses attacker-supplied CBOR) even though it requires a login.
Route::group(['middleware' => ['web', 'auth', 'roles', 'throttle:60,1'], 'roles' => ['user', 'admin'], 'prefix' => \Helper::getSubdirectory(), 'namespace' => 'Modules\Passkeys\Http\Controllers'], function () {
    Route::get('/users/passkeys/{id}', 'PasskeysController@profile')->name('passkeys.profile');
    Route::post('/passkeys/register/options', 'PasskeysController@registerOptions')->name('passkeys.register_options');
    Route::post('/passkeys/register', 'PasskeysController@registerVerify')->name('passkeys.register');
    Route::post('/passkeys/rename/{id}', 'PasskeysController@rename')->name('passkeys.rename');
    Route::post('/passkeys/delete/{id}', 'PasskeysController@destroy')->name('passkeys.delete');
});

// Passkey login - guests. The 'web' group provides the session (challenge
// storage) and CSRF protection. Each endpoint gets its own per-IP throttle
// bucket (keyed by path): the options endpoint is looser because conditional
// mediation calls it automatically on every login-page load, while the
// verification endpoint is tighter. Per-credential failure limiting (which
// avoids locking out everyone behind a shared IP) lives in the controller.
Route::group(['middleware' => ['web'], 'prefix' => \Helper::getSubdirectory(), 'namespace' => 'Modules\Passkeys\Http\Controllers'], function () {
    Route::post('/passkeys/login/options', ['uses' => 'PasskeysController@loginOptions', 'middleware' => 'throttle:60,1'])->name('passkeys.login_options');
    Route::post('/passkeys/login', ['uses' => 'PasskeysController@loginVerify', 'middleware' => 'throttle:30,1'])->name('passkeys.login');
    // Second-factor step, only used when an admin requires 2FA after a passkey login.
    Route::post('/passkeys/login/2fa', ['uses' => 'PasskeysController@loginTwoFactor', 'middleware' => 'throttle:30,1'])->name('passkeys.login_2fa');
});
