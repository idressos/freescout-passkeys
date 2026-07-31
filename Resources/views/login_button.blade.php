{{-- Rendered on the login page. The button stays hidden until the module's
     JS confirms the browser supports WebAuthn in a secure context. --}}
<div class="passkeys-login-block">
    <div id="passkeys-login-alert"></div>
    <button type="button" id="passkeys-login-btn" class="btn btn-default btn-block" style="display:none;">
        {{ __('Login with a passkey') }}
    </button>

    {{-- Shown only if the admin requires a second factor after a passkey login. --}}
    <div id="passkeys-2fa-block" class="passkeys-2fa-block" style="display:none;">
        <p class="passkeys-2fa-help">{{ __('Enter your two-factor authentication code to finish signing in.') }}</p>
        <input type="text" id="passkeys-2fa-code" class="form-control" autocomplete="one-time-code" inputmode="numeric" autocapitalize="off" spellcheck="false" maxlength="64" placeholder="{{ __('Authentication code') }}" />
        <button type="button" id="passkeys-2fa-submit" class="btn btn-primary btn-block">
            {{ __('Verify') }}
        </button>
    </div>
</div>
@include('passkeys::partials/config', ['page' => 'login'])
