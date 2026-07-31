<form class="form-horizontal margin-top margin-bottom" method="POST" action="">
    {{ csrf_field() }}

    <div class="form-group">
        <label class="col-sm-4 control-label">{{ __('Two-factor authentication') }}</label>

        <div class="col-sm-8">
            <div class="controls">
                <div class="onoffswitch-wrap">
                    <div class="onoffswitch">
                        <input type="checkbox" name="settings[passkeys.bypass_2fa]" value="1" id="passkeys_bypass_2fa" class="onoffswitch-checkbox" @if (!empty($settings['passkeys.bypass_2fa']))checked="checked"@endif>
                        <label class="onoffswitch-label" for="passkeys_bypass_2fa"></label>
                    </div>
                </div>
                <p class="form-help">
                    {{ __('When enabled, signing in with a passkey satisfies two-factor authentication, so users who also have 2FA configured are not asked for a second factor after a passkey login. A passkey that requires user verification (PIN or biometric) is already multi-factor.') }}
                    <br>
                    {{ __('When disabled, any installed two-factor-authentication module still applies its second step after a passkey login.') }}
                </p>
            </div>
        </div>
    </div>

    <div class="form-group margin-top">
        <div class="col-sm-8 col-sm-offset-4">
            <button type="submit" class="btn btn-primary">
                {{ __('Save') }}
            </button>
        </div>
    </div>
</form>
