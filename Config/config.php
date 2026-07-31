<?php

return [
    'name' => 'Passkeys',

    // Seconds a WebAuthn challenge stays valid after being issued.
    'challenge_lifetime' => 120,

    // Timeout (seconds) passed to the browser for the WebAuthn ceremonies.
    'ceremony_timeout' => 60,

    // Maximum number of passkeys a user may register.
    'max_passkeys_per_user' => 10,

    // WebAuthn user verification requirement: 'required' (default) demands a
    // PIN/biometric check on the authenticator both when registering and
    // when logging in. Set to 'preferred' only if some of your hardware
    // security keys can not perform user verification - note that passkeys
    // registered while 'required' was active keep working after a change,
    // but keys registered under 'preferred' without UV capability will stop
    // working if you switch back to 'required'.
    'user_verification' => 'required',

    // Maximum failed passkey login attempts per credential per minute.
    'login_rate_limit' => 5,

    // Default for the "passkey login satisfies two-factor authentication"
    // admin setting. When true, a user who logs in with a passkey is not
    // additionally challenged by a two-factor-authentication module (a
    // user-verifying passkey is already multi-factor). When false, any 2FA
    // module still applies its second-factor step after passkey login.
    // The admin setting (Settings » Passkeys) overrides this default.
    'bypass_2fa' => false,
];
