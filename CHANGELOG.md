# Changelog

All notable changes to this module are documented here. This project follows
[Semantic Versioning](https://semver.org).

## 1.0.1

* Added a module icon.
* Login page: the "Login with a passkey" button now sits on the same row as the Login / Forgot buttons, right-justified and styled, instead of full-width below them.
* Profile page: added spacing above the intro text and widened the passkey-name field so its placeholder is no longer cut off.

## 1.0.0

Initial release.

* Register, rename and remove passkeys from the user profile page.
* "Login with a passkey" button on the login page, with passkey autofill
  (conditional UI) in supporting browsers.
* Usernameless login via discoverable credentials; user verification required
  by default.
* Admin setting (Settings » Passkeys) to choose whether a passkey login
  satisfies two-factor authentication; when it must not, a TOTP second step is
  required (fail-closed) for users who have 2FA configured.
* Hardened: single-use context-separated challenges, strict origin check,
  per-credential rate limiting, input size caps, CBOR nesting-depth limit,
  session regeneration, activity-log audit entries, passkey cleanup on user
  deletion.
* Bundled lbuchs/WebAuthn v2.2.0 server library (MIT).
* Compatible with PHP 7.1+ (all versions FreeScout supports).
