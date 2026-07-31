<script type="application/json" id="passkeys-config">{!! json_encode([
    'page' => $page,
    'csrf' => csrf_token(),
    'urls' => $page === 'profile'
        ? [
            'registerOptions' => route('passkeys.register_options'),
            'registerVerify'  => route('passkeys.register'),
        ]
        : [
            'loginOptions'   => route('passkeys.login_options'),
            'loginVerify'    => route('passkeys.login'),
            'loginTwoFactor' => route('passkeys.login_2fa'),
        ],
    'i18n' => [
        'not_supported'      => __('This browser does not support passkeys, or the connection is not secure (HTTPS).'),
        'cancelled'          => __('The passkey operation was cancelled or timed out.'),
        'already_registered' => __('This device or security key is already registered.'),
        'failed'             => __('The passkey operation failed. Please try again.'),
        'rename_prompt'      => __('New passkey name:'),
        'delete_confirm'     => __('Delete this passkey? You will no longer be able to sign in with it.'),
        'twofa_prompt'       => __('Enter your two-factor authentication code to finish signing in.'),
    ],
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) !!}</script>
