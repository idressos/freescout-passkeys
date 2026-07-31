<?php

namespace Modules\Passkeys\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthnException;
use Modules\Passkeys\Entities\Passkey;
use Modules\Passkeys\Services\WebAuthnService;

class PasskeysController extends Controller
{
    /**
     * Authenticator transports the module accepts from the browser.
     */
    public static $valid_transports = ['usb', 'nfc', 'ble', 'hybrid', 'internal', 'smart-card', 'cable'];

    /**
     * Maximum decoded byte sizes accepted for each WebAuthn wire field.
     * Real values are far smaller; these caps stop an oversized payload from
     * driving the CBOR decoder into excessive memory use.
     */
    const MAX_CREDENTIAL_ID = 1023;   // spec maximum for a credential ID
    const MAX_CLIENT_DATA   = 4096;
    const MAX_AUTH_DATA     = 4096;
    const MAX_SIGNATURE     = 1024;
    const MAX_USER_HANDLE   = 256;
    const MAX_ATTESTATION   = 16384;

    // Session key + lifetime for the "passkey verified, awaiting the second
    // factor" state (used only when an admin requires 2FA after passkey login).
    const TWO_FACTOR_KEY = 'passkeys_2fa_pending';
    const TWO_FACTOR_TTL = 300;

    /**
     * Passkey management page. Strictly limited to the user's own profile.
     */
    public function profile($id, Request $request)
    {
        $user = Auth::user();

        // Users can only ever manage their own passkeys.
        if (!$user || (int)$id !== (int)$user->id) {
            \Helper::denyAccess();
        }

        $passkeys = Passkey::where('user_id', $user->id)
            ->orderBy('created_at')
            ->get();

        return view('passkeys::profile', [
            'user' => $user,
            'passkeys' => $passkeys,
            'runtime_supported' => WebAuthnService::isRuntimeSupported(),
            'is_https' => $this->appUsesHttps(),
        ]);
    }

    /**
     * Step 1 of registration: issue PublicKeyCredentialCreationOptions.
     */
    public function registerOptions(Request $request)
    {
        if (!WebAuthnService::isRuntimeSupported()) {
            return $this->errorResponse(__('Passkeys are not supported by the server configuration (OpenSSL is required).'));
        }

        $user = Auth::user();

        $existing = Passkey::where('user_id', $user->id)->get();

        $max = (int)config('passkeys.max_passkeys_per_user', 10);
        if (count($existing) >= $max) {
            return $this->errorResponse(__('You have reached the maximum number of passkeys (:max).', ['max' => $max]));
        }

        // Prevent registering the same authenticator twice.
        $exclude_ids = [];
        foreach ($existing as $passkey) {
            $raw_id = base64_decode($passkey->credential_id, true);
            if (is_string($raw_id) && $raw_id !== '') {
                $exclude_ids[] = $raw_id;
            }
        }

        try {
            $webauthn = WebAuthnService::server();

            $create_args = $webauthn->getCreateArgs(
                (string)$user->id,
                (string)$user->email,
                (string)$user->getFullName(),
                (int)config('passkeys.ceremony_timeout', 60),
                // Discoverable credential, so that usernameless login works.
                'required',
                config('passkeys.user_verification', 'required'),
                null,
                $exclude_ids
            );

            WebAuthnService::storeChallenge(WebAuthnService::CONTEXT_REGISTER, $webauthn->getChallenge());
        } catch (\Throwable $e) {
            \Helper::logException($e, '[Passkeys] ');

            return $this->errorResponse(__('Could not start passkey registration.'));
        }

        return \Response::json([
            'status' => 'success',
            'options' => $create_args,
        ]);
    }

    /**
     * Step 2 of registration: verify the authenticator response and store
     * the new credential.
     */
    public function registerVerify(Request $request)
    {
        $user = Auth::user();

        // Decode the browser response. Each field is capped at a realistic
        // size so an oversized payload can not drive the CBOR decoder into
        // excessive memory use.
        $client_data_json = $this->base64UrlDecode($request->input('clientDataJSON'), self::MAX_CLIENT_DATA);
        $attestation_object = $this->base64UrlDecode($request->input('attestationObject'), self::MAX_ATTESTATION);

        if ($client_data_json === null || $attestation_object === null) {
            return $this->errorResponse(__('Invalid passkey registration data.'));
        }

        // Defense in depth: exact origin match against APP_URL, in addition
        // to the library's own origin/RP ID validation.
        if (!WebAuthnService::verifyExactOrigin($client_data_json)) {
            return $this->errorResponse(__('Invalid origin. Make sure you are accessing the helpdesk via :url.', ['url' => WebAuthnService::expectedOrigin()]));
        }

        // The challenge the client claims it signed must be one we issued for
        // a registration ceremony. Consuming it makes it single-use, so a
        // failed attempt can not be replayed.
        $presented_challenge = WebAuthnService::clientChallenge($client_data_json);

        if ($presented_challenge === null) {
            return $this->errorResponse(__('Invalid passkey registration data.'));
        }

        $challenge = WebAuthnService::consumeChallenge(WebAuthnService::CONTEXT_REGISTER, $presented_challenge);

        if ($challenge === null) {
            return $this->errorResponse(__('The passkey registration session has expired. Please try again.'));
        }

        try {
            $webauthn = WebAuthnService::server();

            $data = $webauthn->processCreate(
                $client_data_json,
                $attestation_object,
                $challenge,
                config('passkeys.user_verification', 'required') === 'required',
                true
            );
        } catch (\Throwable $e) {
            // \Throwable (not \Exception) so PHP 8 TypeError/Error subclasses
            // raised on malformed input can never escape as a 500.
            \Helper::logException($e, '[Passkeys] Registration failed: ');

            return $this->errorResponse(__('The passkey could not be verified. Please try again.'));
        }

        $raw_credential_id = $data->credentialId;

        if (!is_string($raw_credential_id) || $raw_credential_id === '' || strlen($raw_credential_id) > 1023
            || !is_string($data->credentialPublicKey) || strpos($data->credentialPublicKey, 'PUBLIC KEY') === false
        ) {
            return $this->errorResponse(__('Invalid passkey registration data.'));
        }

        // A credential ID identifies one authenticator - it can only ever
        // belong to one account.
        if (Passkey::findByRawCredentialId($raw_credential_id)) {
            return $this->errorResponse(__('This passkey is already registered.'));
        }

        $max = (int)config('passkeys.max_passkeys_per_user', 10);
        if (Passkey::where('user_id', $user->id)->count() >= $max) {
            return $this->errorResponse(__('You have reached the maximum number of passkeys (:max).', ['max' => $max]));
        }

        $passkey = new Passkey();
        $passkey->name = $this->sanitizeName($request->input('name'));
        $passkey->user_id = $user->id;
        $passkey->credential_id = base64_encode($raw_credential_id);
        $passkey->credential_id_hash = hash('sha256', $raw_credential_id);
        $passkey->public_key = $data->credentialPublicKey;
        $passkey->sign_count = is_int($data->signatureCounter) ? $data->signatureCounter : 0;
        $passkey->transports = $this->sanitizeTransports($request->input('transports'));
        $passkey->aaguid = $this->formatAaguid($data->AAGUID);

        try {
            $passkey->save();
        } catch (\Exception $e) {
            // Unique index on the credential ID hash guards against a race
            // between the duplicate check above and this insert.
            \Helper::logException($e, '[Passkeys] ');

            return $this->errorResponse(__('The passkey could not be saved. Please try again.'));
        }

        $this->audit($user, 'added a passkey', $passkey->name);

        \Session::flash('flash_success_floating', __('Passkey has been added.'));

        return \Response::json([
            'status' => 'success',
        ]);
    }

    /**
     * Rename one of the user's own passkeys. Regular form POST.
     */
    public function rename($id, Request $request)
    {
        $passkey = Passkey::where('id', (int)$id)
            ->where('user_id', Auth::id())
            ->first();

        if (!$passkey) {
            \Helper::denyAccess();
        }

        $name = $this->sanitizeName($request->input('name'), '');

        if ($name === '') {
            \Session::flash('flash_error_floating', __('Passkey name is required.'));

            return redirect()->route('passkeys.profile', ['id' => Auth::id()]);
        }

        $passkey->name = $name;
        $passkey->save();

        $this->audit(Auth::user(), 'renamed a passkey', $name);

        \Session::flash('flash_success_floating', __('Passkey has been renamed.'));

        return redirect()->route('passkeys.profile', ['id' => Auth::id()]);
    }

    /**
     * Delete one of the user's own passkeys. Regular form POST.
     */
    public function destroy($id, Request $request)
    {
        $passkey = Passkey::where('id', (int)$id)
            ->where('user_id', Auth::id())
            ->first();

        if (!$passkey) {
            \Helper::denyAccess();
        }

        $name = $passkey->name;
        $passkey->delete();

        $this->audit(Auth::user(), 'deleted a passkey', $name);

        \Session::flash('flash_success_floating', __('Passkey has been deleted.'));

        return redirect()->route('passkeys.profile', ['id' => Auth::id()]);
    }

    /**
     * Step 1 of login: issue PublicKeyCredentialRequestOptions.
     *
     * No allowCredentials list is sent (usernameless flow with discoverable
     * credentials), so this endpoint discloses nothing about users.
     */
    public function loginOptions(Request $request)
    {
        if (Auth::check()) {
            return $this->errorResponse(__('You are already logged in.'));
        }

        if (!WebAuthnService::isRuntimeSupported()) {
            return $this->errorResponse(__('Passkeys are not supported by the server configuration.'));
        }

        try {
            $webauthn = WebAuthnService::server();

            $get_args = $webauthn->getGetArgs(
                [],
                (int)config('passkeys.ceremony_timeout', 60),
                true,
                true,
                true,
                true,
                true,
                config('passkeys.user_verification', 'required')
            );

            WebAuthnService::storeChallenge(WebAuthnService::CONTEXT_LOGIN, $webauthn->getChallenge());
        } catch (\Throwable $e) {
            \Helper::logException($e, '[Passkeys] ');

            return $this->errorResponse(__('Could not start passkey login.'));
        }

        return \Response::json([
            'status' => 'success',
            'options' => $get_args,
        ]);
    }

    /**
     * Step 2 of login: verify the assertion and authenticate the user.
     */
    public function loginVerify(Request $request)
    {
        if (Auth::check()) {
            return \Response::json([
                'status' => 'success',
                'redirect' => $this->loginRedirectUrl($request),
            ]);
        }

        $limiter = app(\Illuminate\Cache\RateLimiter::class);
        $max_attempts = (int)config('passkeys.login_rate_limit', 5);

        $raw_credential_id = $this->base64UrlDecode($request->input('id'), self::MAX_CREDENTIAL_ID);
        $client_data_json = $this->base64UrlDecode($request->input('clientDataJSON'), self::MAX_CLIENT_DATA);
        $authenticator_data = $this->base64UrlDecode($request->input('authenticatorData'), self::MAX_AUTH_DATA);
        $signature = $this->base64UrlDecode($request->input('signature'), self::MAX_SIGNATURE);
        $user_handle = $request->filled('userHandle') ? $this->base64UrlDecode($request->input('userHandle'), self::MAX_USER_HANDLE) : null;

        // Rate limit per presented credential (falling back to a per-session
        // key for junk input). Keying on the credential - not on the raw IP -
        // means one attacker can not lock out every user sharing a NAT/proxy
        // address; at worst they throttle the single credential they target.
        $throttle_key = 'passkeys-login|' . ($raw_credential_id !== null
            ? hash('sha256', $raw_credential_id)
            : 'nocred|' . \Session::getId());

        if ($limiter->tooManyAttempts($throttle_key, $max_attempts, 1)) {
            return $this->errorResponse(__('Too many failed attempts. Please try again in a minute.'), 429);
        }

        if ($raw_credential_id === null || $client_data_json === null || $authenticator_data === null || $signature === null) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        // Defense in depth: exact origin match against APP_URL.
        if (!WebAuthnService::verifyExactOrigin($client_data_json)) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        $presented_challenge = WebAuthnService::clientChallenge($client_data_json);

        if ($presented_challenge === null) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        $passkey = Passkey::findByRawCredentialId($raw_credential_id);

        if (!$passkey) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        // The userHandle returned by the authenticator must identify the
        // same user the credential belongs to.
        if ($user_handle !== null && $user_handle !== '' && !hash_equals((string)$passkey->user_id, $user_handle)) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        $user = User::find($passkey->user_id);

        if (!$user || !$this->userCanLogIn($user)) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        // Consume the login challenge (single-use) only once we have a real
        // candidate credential to verify against.
        $challenge = WebAuthnService::consumeChallenge(WebAuthnService::CONTEXT_LOGIN, $presented_challenge);

        if ($challenge === null) {
            return $this->loginFailed($limiter, $throttle_key);
        }

        try {
            $webauthn = WebAuthnService::server();

            $webauthn->processGet(
                $client_data_json,
                $authenticator_data,
                $signature,
                $passkey->public_key,
                $challenge,
                (int)$passkey->sign_count,
                config('passkeys.user_verification', 'required') === 'required',
                true
            );

            $new_sign_count = $webauthn->getSignatureCounter();
        } catch (\Throwable $e) {
            // Do not log the exception here: on this guest-reachable path a
            // failure is attacker-controllable, and logging it would both
            // flood the log and leak (via the disk write) whether a
            // credential exists. \Throwable also absorbs PHP 8 Errors.
            return $this->loginFailed($limiter, $throttle_key);
        }

        if (is_int($new_sign_count)) {
            $passkey->sign_count = $new_sign_count;
        }
        $passkey->last_used_at = now();
        $passkey->save();

        $limiter->clear($throttle_key);

        // If an admin has decided that a passkey login must NOT satisfy
        // two-factor authentication, and this user has a second factor
        // configured, require it before establishing the session. The passkey
        // is the first factor; the session is not created yet.
        if ($this->needsSecondFactor($user)) {
            \Session::put(self::TWO_FACTOR_KEY, [
                'user_id' => (int) $user->id,
                'expires_at' => time() + self::TWO_FACTOR_TTL,
            ]);

            $this->audit($user, 'verified a passkey (second factor required)', $passkey->name);

            return \Response::json([
                'status' => 'success',
                'two_factor_required' => true,
            ]);
        }

        $this->audit($user, 'logged in with a passkey', $passkey->name);

        return $this->completeLogin($request, $user);
    }

    /**
     * Step 3 (only when 2FA is required after a passkey login): verify the
     * user's TOTP / recovery code and finish establishing the session.
     */
    public function loginTwoFactor(Request $request)
    {
        if (Auth::check()) {
            return \Response::json([
                'status' => 'success',
                'redirect' => $this->loginRedirectUrl($request),
            ]);
        }

        $pending = \Session::get(self::TWO_FACTOR_KEY);

        if (!is_array($pending) || empty($pending['user_id']) || empty($pending['expires_at'])
            || time() > (int) $pending['expires_at']
        ) {
            \Session::forget(self::TWO_FACTOR_KEY);

            return $this->errorResponse(__('Your login session has expired. Please try again.'));
        }

        $limiter = app(\Illuminate\Cache\RateLimiter::class);
        $throttle_key = 'passkeys-2fa|' . (int) $pending['user_id'];

        if ($limiter->tooManyAttempts($throttle_key, (int) config('passkeys.login_rate_limit', 5), 1)) {
            return $this->errorResponse(__('Too many failed attempts. Please try again in a minute.'), 429);
        }

        $user = User::find((int) $pending['user_id']);

        // Re-check everything: the account must still be loginable and still
        // require (and support) a second factor. Fails closed otherwise.
        if (!$user || !$this->userCanLogIn($user) || !$this->needsSecondFactor($user)) {
            \Session::forget(self::TWO_FACTOR_KEY);

            return $this->errorResponse(__('The passkey could not be verified.'));
        }

        $code = $request->input('code');
        $code = is_string($code) ? preg_replace('/\s+/', '', $code) : '';

        if ($code === '' || strlen($code) > 64) {
            $limiter->hit($throttle_key, 1);

            return $this->errorResponse(__('Invalid authentication code.'));
        }

        // Validate through the 2FA module's own public API. If that API is not
        // available we fail closed (never skip the second factor).
        $valid = false;

        if (method_exists($user, 'validateTwoFactorCode')) {
            try {
                $valid = (bool) $user->validateTwoFactorCode($code);
            } catch (\Throwable $e) {
                $valid = false;
            }
        }

        if (!$valid) {
            $limiter->hit($throttle_key, 1);

            return $this->errorResponse(__('Invalid authentication code.'));
        }

        \Session::forget(self::TWO_FACTOR_KEY);
        $limiter->clear($throttle_key);

        $this->audit($user, 'completed two-factor authentication after a passkey login', '');

        return $this->completeLogin($request, $user);
    }

    /**
     * Establish the authenticated session for a verified user. No "remember
     * me" cookie is set for passkey logins; the session ID is regenerated to
     * prevent session fixation.
     */
    protected function completeLogin(Request $request, User $user)
    {
        Auth::guard()->login($user, false);

        $request->session()->regenerate();

        return \Response::json([
            'status' => 'success',
            'redirect' => $this->loginRedirectUrl($request),
        ]);
    }

    /**
     * Whether a second factor must be collected after a passkey login: the
     * admin has NOT allowed passkeys to satisfy 2FA, a 2FA module is present,
     * and this user has a second factor enabled. Any uncertainty errs toward
     * NOT requiring it here - the caller only reaches this after a valid
     * passkey assertion, and the check is re-run before completing 2FA.
     *
     * @return bool
     */
    protected function needsSecondFactor(User $user)
    {
        $bypass = (bool) \Option::get('passkeys.bypass_2fa', config('passkeys.bypass_2fa', false));

        if ($bypass || !method_exists($user, 'hasTwoFactorEnabled')) {
            return false;
        }

        try {
            return (bool) $user->hasTwoFactorEnabled();
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Register the failed attempt and return a deliberately generic error,
     * so the endpoint does not leak whether a credential/user exists.
     */
    protected function loginFailed($limiter, $throttle_key)
    {
        $limiter->hit($throttle_key, 1);

        return $this->errorResponse(__('The passkey could not be verified.'));
    }

    /**
     * Whether the account is allowed to authenticate.
     */
    protected function userCanLogIn(User $user)
    {
        // FreeScout marks disabled/deleted users via the status field.
        // (Core's LogoutIfDeleted middleware also enforces this on every
        // subsequent request - this is the first gate.)
        if (!$user->isActive()) {
            return false;
        }

        // Invited users who never set a password can not log in yet.
        if (empty($user->password)) {
            return false;
        }

        return true;
    }

    /**
     * Where to send the user after a successful passkey login. Only paths
     * on this FreeScout instance are allowed (no open redirect).
     */
    protected function loginRedirectUrl(Request $request)
    {
        $default = route('dashboard');

        $intended = \Session::pull('url.intended');

        if (!is_string($intended) || $intended === '') {
            return $default;
        }

        // Reject any backslash or control/whitespace character up front.
        // Browsers treat "\" as "/" and strip TAB/CR/LF, so these bytes let a
        // URL that parse_url() reads as same-host resolve to a foreign host.
        if (preg_match('/[\\\\\x00-\x20\x7F]/', $intended)) {
            return $default;
        }

        $scheme = parse_url($intended, PHP_URL_SCHEME);
        $scheme = is_string($scheme) ? strtolower($scheme) : $scheme;
        $host = parse_url($intended, PHP_URL_HOST);

        // Relative URLs (no scheme/host) are fine; absolute ones must point
        // to this application's host over the same scheme.
        if ($host !== null && $host !== '') {
            $app_host = parse_url(config('app.url'), PHP_URL_HOST);

            if (!in_array($scheme, ['http', 'https'], true)
                || $scheme !== WebAuthnService::appScheme()
                || strcasecmp($host, (string)$app_host) !== 0
            ) {
                return $default;
            }
        } elseif (strpos($intended, '/') !== 0 || strpos($intended, '//') === 0) {
            // Must be a root-relative path, and not "//" (protocol-relative).
            return $default;
        }

        return $intended;
    }

    /**
     * Strict base64url decoding, capped at $maxBytes decoded. Returns null on
     * any irregularity (wrong charset, oversized input, invalid base64).
     *
     * @param mixed $value
     * @param int $maxBytes maximum allowed decoded size
     * @return string|null
     */
    protected function base64UrlDecode($value, $maxBytes = 1024)
    {
        // Cap the *encoded* length first, so oversized input is rejected
        // before any decoding work. 4 base64 chars encode 3 bytes.
        $maxEncoded = (int) (ceil($maxBytes / 3) * 4) + 4;

        // The 'D' modifier anchors $ to the very end, so a trailing newline
        // can not sneak past the charset check.
        if (!is_string($value) || $value === '' || strlen($value) > $maxEncoded
            || !preg_match('/^[a-zA-Z0-9_\-]+$/D', $value)
        ) {
            return null;
        }

        $b64 = strtr($value, '-_', '+/');
        $b64 .= str_repeat('=', (4 - strlen($b64) % 4) % 4);

        $decoded = base64_decode($b64, true);

        if (!is_string($decoded) || strlen($decoded) > $maxBytes) {
            return null;
        }

        return $decoded;
    }

    /**
     * @param mixed $name
     * @param string|null $default value returned when the name is empty
     *                             (null = a generated default name)
     * @return string
     */
    protected function sanitizeName($name, $default = null)
    {
        $name = is_string($name) ? trim($name) : '';
        // Strip control characters.
        $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name);

        if (!is_string($name)) {
            $name = '';
        }

        if (trim($name) === '') {
            $name = $default !== null ? $default : __('Passkey') . ' ' . date('Y-m-d');
        }

        // Bound the length in all cases (a long translation of the default
        // must still fit the name column).
        return mb_substr($name, 0, 64);
    }

    /**
     * @return string|null JSON array of whitelisted transports
     */
    protected function sanitizeTransports($transports)
    {
        if (!is_array($transports)) {
            return null;
        }

        // Intersect against the whitelist (whitelist first so the result is
        // capped at the number of known transports), de-duplicate, and cap.
        $clean = array_values(array_unique(array_intersect(
            self::$valid_transports,
            array_filter($transports, 'is_string')
        )));

        $clean = array_slice($clean, 0, count(self::$valid_transports));

        return count($clean) ? json_encode($clean) : null;
    }

    /**
     * Convert the raw 16-byte AAGUID returned by the library into a standard
     * UUID string (or null if it is absent / all-zero).
     *
     * @param mixed $aaguid raw binary string, or a ByteBuffer
     * @return string|null
     */
    protected function formatAaguid($aaguid)
    {
        if (is_object($aaguid) && method_exists($aaguid, 'getBinaryString')) {
            $aaguid = $aaguid->getBinaryString();
        }

        if (!is_string($aaguid) || strlen($aaguid) !== 16 || trim($aaguid, "\0") === '') {
            return null;
        }

        $hex = bin2hex($aaguid);

        return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-' . substr($hex, 16, 4) . '-' . substr($hex, 20);
    }

    /**
     * Write an entry to FreeScout's activity log for a passkey change, so the
     * account owner and admins have an audit trail. Never breaks the request.
     *
     * @param \App\User $user
     * @param string $description
     * @param string $passkey_name
     * @return void
     */
    protected function audit($user, $description, $passkey_name)
    {
        try {
            if (!$user || !function_exists('activity')) {
                return;
            }

            activity()
                ->causedBy($user)
                ->performedOn($user)
                ->withProperties(['passkey' => (string) $passkey_name, 'ip' => request()->ip()])
                ->useLog('users')
                ->log($description);
        } catch (\Throwable $e) {
            // Auditing must never interfere with the user-facing action.
        }
    }

    /**
     * @return bool
     */
    protected function appUsesHttps()
    {
        $scheme = parse_url(config('app.url'), PHP_URL_SCHEME);
        $host = parse_url(config('app.url'), PHP_URL_HOST);

        return $scheme === 'https' || $host === 'localhost' || $host === '127.0.0.1';
    }

    /**
     * @return \Illuminate\Http\JsonResponse
     */
    protected function errorResponse($message, $http_code = 200)
    {
        return \Response::json([
            'status' => 'error',
            'message' => $message,
        ], $http_code);
    }
}
