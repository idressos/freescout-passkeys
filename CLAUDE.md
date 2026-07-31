# CLAUDE.md — Passkeys module for FreeScout

Guidance for working on this repository. Read this first.

## What this is

A FreeScout module adding **passkey (WebAuthn / FIDO2) login**: users register /
rename / remove passkeys on their profile, and a "Login with a passkey" button
(plus autofill) on the login page. Passwordless, usernameless, discoverable
credentials with user verification.

- **Lead Developer:** Ioannis Dressos <idressos@outlook.com>
- **License:** AGPL-3.0-or-later (FreeScout requires modules be AGPL-3.0). No
  warranty / no liability — see `LICENSE` and `README.md`.
- **This repo's root IS the module folder.** When installed it lives at
  `Modules/Passkeys/` inside a FreeScout install. If cloned from GitHub the
  folder is `freescout-passkeys` and must be renamed to `Passkeys`.

## Hard constraints (do not break)

1. **PHP 7.1+ compatibility.** FreeScout supports PHP 7.1 through 8.x. Do NOT
   use syntax/functions newer than 7.1 in module code. The one exception is the
   bundled library's `str_starts_with`, covered by `Vendor/polyfill.php`. Never
   assume the local PHP version is the target. Verify with PHPCompatibility (see
   "Verifying").
2. **FreeScout runs Laravel 5.5.40** (pinned, never upgraded). Use only APIs
   available there. No anonymous-class migrations, no Laravel 6+ helpers.
3. **Security first.** This is an authentication module published publicly. Every
   change must preserve the invariants in "Security model" below. When in doubt,
   fail closed.
4. **Self-contained.** No Composer install at runtime; the WebAuthn library is
   vendored and hand-autoloaded (`start.php`). Do not add runtime Composer deps.

## Layout

```
module.json                 Module manifest (name, alias "passkeys", version, provider)
composer.json               Metadata only (PSR-4 Modules\Passkeys\); not used at runtime
start.php                   Autoloads vendored lib + polyfill, loads routes
Config/config.php           Defaults: challenge lifetime, timeouts, limits, user_verification, bypass_2fa
Http/routes.php             Routes: management (web,auth,roles,throttle) + guest login (web,throttle)
Http/Controllers/PasskeysController.php   All endpoints (register/login/rename/delete/2fa)
Services/WebAuthnService.php              RP id/origin, challenge store, server() factory
Entities/Passkey.php        Eloquent model (table "passkeys")
Database/Migrations/        passkeys table
Providers/PasskeysServiceProvider.php     Hooks, views, settings section, user-delete cleanup
Resources/views/            profile, login_button, settings, partials/{config,profile_menu}
Public/{css,js}/passkeys.*  Frontend (vanilla JS, CSP-safe: config via <script type=application/json>)
Vendor/WebAuthn/            Bundled lbuchs/WebAuthn v2.2.0 (MIT) + MODIFICATIONS.md
Vendor/polyfill.php         str_starts_with polyfill for PHP < 8
tests/webauthn_roundtrip.php  Self-contained crypto + CBOR test (no FreeScout needed)
```

## How it plugs into FreeScout (Eventy hooks)

- `login_form.after` — renders the login button (`Resources/views/login_button.blade.php`).
- `user.profile.menu.after_profile` — adds the "Passkeys" sidebar item, self only.
- `stylesheets` / `javascripts` — inject assets, but only on `login` and
  `passkeys.profile` routes.
- `settings.sections` / `settings.section_settings` / `settings.section_params` /
  `settings.view` — the admin **Settings » Passkeys** section (option
  `passkeys.bypass_2fa`, stored via `\Option`).
- `\App\User::updated` / `::deleted` — delete a user's passkeys when their
  account is deleted.

Routes are namespaced `passkeys.*`, prefixed with `\Helper::getSubdirectory()`.
Assets are referenced via `\Module::getPublicPath('passkeys')`.

## Security model — invariants (never weaken)

- **Challenges**: single-use, session-bound, context-separated (register vs
  login can't be swapped), short expiry, matched against the client-presented
  value; capped FIFO so concurrent ceremonies (autofill + button) coexist.
- **Origin**: `WebAuthnService::verifyExactOrigin()` does an EXACT match against
  `APP_URL` before trust — the bundled lib's own check is only a loose suffix
  match. This exact check must run before every `processCreate`/`processGet`.
- **Credential → user binding**: the user is always `$passkey->user_id`; the
  signature is always checked against that credential's stored public key.
- **Input**: every WebAuthn field is size-capped (`MAX_*` consts) before
  decoding; base64url regex is anchored (`/D`); the bundled CBOR decoder has a
  nesting-depth limit (see `Vendor/WebAuthn/MODIFICATIONS.md`).
- **Errors**: catch `\Throwable` (not just `\Exception`) around library calls so
  PHP 8 `Error`s can never 500 the login page. Guest login-failure paths must
  NOT log exceptions (enumeration + log-flood).
- **Rate limiting**: login failures are keyed per credential (not raw IP) to
  avoid shared-NAT lockout; endpoints also have route-level throttles.
- **Login**: only `isActive()` users with a password; `Auth::guard()->login($u,
  false)` (no remember cookie) then `session()->regenerate()`.
- **Redirect**: `loginRedirectUrl()` rejects backslashes/control chars and only
  allows same-host-same-scheme absolute URLs or clean root-relative paths.
- **2FA** (`passkeys.bypass_2fa`): default true = passkey completes (already
  MFA). False = if the user has 2FA, require a TOTP step via the 2FA module's
  `validateTwoFactorCode()`, guarded by `method_exists` and **fail-closed**.
  FreeScout's 2FA module only gates the password `/login` path, so programmatic
  passkey login bypasses it unless we enforce it ourselves.

Before shipping any change here, re-read this list and confirm none is weakened.

## Verifying (run before every commit)

```bash
# 1. Syntax — all PHP files
find . -name '*.php' -print0 | xargs -0 -n1 php -l | grep -v 'No syntax errors'

# 2. JS syntax
node --check Public/js/passkeys.js

# 3. Crypto + CBOR round-trip (self-contained, must exit 0)
php tests/webauthn_roundtrip.php

# 4. PHP 7.1+ compatibility (install once, then run)
#    composer require --dev phpcompatibility/php-compatibility dealerdirect/phpcodesniffer-composer-installer
#    (allow the plugin) then:
vendor/bin/phpcs --standard=PHPCompatibility --runtime-set testVersion 7.1- --extensions=php .
# The only acceptable "error" is sodium_crypto_sign_verify_detached in the
# vendored lib — it is guarded by function_exists(), a false positive.
```

Facade-dependent logic (challenge session store, rate limiting, redirect guard,
2FA gating) is pure enough to test by replicating the algorithm; there is no
Laravel test harness here. If you change that logic, reason through it carefully
and, where practical, add a case to a throwaway script mirroring the function.

## Git workflow

- **Remote:** `origin` = https://github.com/idressos/freescout-passkeys
  (account `idressos`, HTTPS). Repo root = this folder.
- **Commits:** split bulk work into separate **logical** commits. Messages are
  **short and to the point** — no long bodies unless truly necessary. **Never**
  add `Co-Authored-By` or any assistant/AI co-author line.
- **Push:** when a batch is tested + complete, push automatically.
- **Versioning (semver):** bump automatically by change scale — PATCH (fixes),
  MINOR (new backward-compatible feature), MAJOR (breaking). Update the version
  in **`module.json`** and add a **`CHANGELOG.md`** entry in the same batch.

## Gotchas

- The public symlink `public/modules/passkeys` → `Public/` is created by
  FreeScout on activation; asset filters guard with `file_exists()`.
- `APP_URL` must exactly match the browser address (scheme/host/port) — it is
  the RP ID and expected origin. Mismatch = "invalid origin" on every operation.
- Blade view namespace is `passkeys::`. The JS boots from a
  `<script type="application/json" id="passkeys-config">` block (CSP-safe) — no
  inline executable JS.
- WebAuthn requires a secure context (HTTPS, or http://localhost for dev).
