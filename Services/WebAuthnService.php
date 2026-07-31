<?php

namespace Modules\Passkeys\Services;

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\Binary\ByteBuffer;

/**
 * Thin wrapper around the bundled lbuchs/WebAuthn library that pins down the
 * security-relevant parameters (Relying Party ID, expected origin, challenge
 * lifecycle) so the controller cannot get them wrong.
 */
class WebAuthnService
{
    // Session key holding the list of pending (unconsumed) challenges.
    const SESSION_KEY = 'passkeys_challenges';

    // Maximum number of concurrent pending challenges kept per session. This
    // lets a login page use conditional mediation and the explicit button at
    // the same time (or several tabs) without one clobbering the other, while
    // still bounding how much a client can make us store.
    const MAX_CHALLENGES = 5;

    const CONTEXT_REGISTER = 'register';
    const CONTEXT_LOGIN = 'login';

    /**
     * Parsed scheme of APP_URL, always lower-cased. Defaults to https.
     *
     * @return string
     */
    public static function appScheme()
    {
        $scheme = parse_url(config('app.url'), PHP_URL_SCHEME);

        return strtolower(is_string($scheme) && $scheme !== '' ? $scheme : 'https');
    }

    /**
     * Relying Party ID: the effective domain of APP_URL (no scheme, no port).
     *
     * @return string
     */
    public static function rpId()
    {
        $host = parse_url(config('app.url'), PHP_URL_HOST);

        return strtolower(is_string($host) && $host !== '' ? $host : 'localhost');
    }

    /**
     * The exact origin the browser must report in clientDataJSON,
     * derived from APP_URL: scheme://host[:port], no trailing slash.
     *
     * @return string
     */
    public static function expectedOrigin()
    {
        $scheme = self::appScheme();
        $host = self::rpId();
        $port = parse_url(config('app.url'), PHP_URL_PORT);

        $origin = $scheme.'://'.$host;

        if ($port && !($scheme === 'https' && (int) $port === 443) && !($scheme === 'http' && (int) $port === 80)) {
            $origin .= ':'.(int) $port;
        }

        return $origin;
    }

    /**
     * Human-readable Relying Party name shown by authenticators.
     *
     * @return string
     */
    public static function rpName()
    {
        $name = \Option::get('company_name');

        if (!$name) {
            $name = config('app.name', 'FreeScout');
        }

        return (string) $name;
    }

    /**
     * Build the WebAuthn server instance.
     *
     * Attestation formats are restricted to 'none' (the library then also
     * requests attestation 'none' from the browser): standard practice for
     * passkeys - no hardware attestation data is collected, and the server
     * never parses complex attestation statements (smaller attack surface).
     *
     * @return WebAuthn
     */
    public static function server()
    {
        // true = binary values are serialized as base64url strings in JSON.
        return new WebAuthn(self::rpName(), self::rpId(), array('none'), true);
    }

    /**
     * Strict origin comparison, ON TOP OF the library's own check.
     *
     * SECURITY: the bundled library's _checkOrigin() is only a suffix match
     * (WebAuthn.php), so it would accept e.g. "evilhelpdesk.example.com" for
     * an RP ID of "helpdesk.example.com". This exact-equality check is what
     * closes that gap - it MUST run before trusting any ceremony and MUST
     * NOT be removed.
     *
     * @param string $clientDataJSON raw (binary) clientDataJSON
     * @return bool
     */
    public static function verifyExactOrigin($clientDataJSON)
    {
        $clientData = is_string($clientDataJSON) ? json_decode($clientDataJSON) : null;

        if (!is_object($clientData) || !isset($clientData->origin) || !is_string($clientData->origin)) {
            return false;
        }

        return hash_equals(self::expectedOrigin(), strtolower(rtrim($clientData->origin, '/')));
    }

    /**
     * Safely extract the challenge the client claims it signed, from the raw
     * clientDataJSON. Returns the raw binary challenge, or null if the JSON
     * is malformed or the type/challenge fields are not the expected strings.
     *
     * Validating that "type" and "challenge" are strings here means the
     * bundled library never receives a non-string challenge (which would
     * raise an uncatchable-by-\Exception TypeError on PHP 8).
     *
     * @param string $clientDataJSON
     * @return string|null
     */
    public static function clientChallenge($clientDataJSON)
    {
        if (!is_string($clientDataJSON)) {
            return null;
        }

        $clientData = json_decode($clientDataJSON);

        if (!is_object($clientData)
            || !isset($clientData->type) || !is_string($clientData->type)
            || !isset($clientData->challenge) || !is_string($clientData->challenge)
        ) {
            return null;
        }

        $b64 = strtr($clientData->challenge, '-_', '+/');
        $b64 .= str_repeat('=', (4 - strlen($b64) % 4) % 4);

        $raw = base64_decode($b64, true);

        return is_string($raw) && strlen($raw) >= 16 ? $raw : null;
    }

    /**
     * Store a single-use, short-lived challenge in the user's session.
     *
     * @param string $context self::CONTEXT_REGISTER or self::CONTEXT_LOGIN
     * @param ByteBuffer $challenge
     * @return void
     */
    public static function storeChallenge($context, ByteBuffer $challenge)
    {
        $now = time();
        $list = self::pendingChallenges($now);

        $list[] = array(
            'context' => $context,
            'challenge' => base64_encode($challenge->getBinaryString()),
            'expires_at' => $now + (int) config('passkeys.challenge_lifetime', 120),
        );

        // Keep only the most recent MAX_CHALLENGES entries.
        if (count($list) > self::MAX_CHALLENGES) {
            $list = array_slice($list, -self::MAX_CHALLENGES);
        }

        \Session::put(self::SESSION_KEY, $list);
    }

    /**
     * Consume the pending challenge that matches both the ceremony context
     * and the exact value the client presented (single-use). Any expired or
     * malformed entries are pruned as a side effect. A challenge can never be
     * consumed twice, and a register challenge can never satisfy a login
     * (or vice-versa) because the context must match.
     *
     * @param string $context
     * @param string $presentedRaw raw binary challenge from clientDataJSON
     * @return string|null the raw binary challenge, or null
     */
    public static function consumeChallenge($context, $presentedRaw)
    {
        if (!is_string($presentedRaw) || strlen($presentedRaw) < 16) {
            return null;
        }

        $now = time();
        $matched = null;
        $remaining = array();

        foreach (self::pendingChallenges($now) as $entry) {
            $raw = base64_decode($entry['challenge'], true);

            if ($matched === null
                && is_string($raw)
                && hash_equals((string) $context, (string) $entry['context'])
                && hash_equals($raw, $presentedRaw)
            ) {
                // Consume this one - do not carry it over.
                $matched = $raw;
                continue;
            }

            $remaining[] = $entry;
        }

        \Session::put(self::SESSION_KEY, $remaining);

        return $matched;
    }

    /**
     * Return the current non-expired, well-formed pending challenge entries.
     *
     * @param int $now
     * @return array
     */
    protected static function pendingChallenges($now)
    {
        $list = \Session::get(self::SESSION_KEY, array());

        if (!is_array($list)) {
            return array();
        }

        $valid = array();

        foreach ($list as $entry) {
            if (is_array($entry)
                && !empty($entry['context'])
                && !empty($entry['challenge'])
                && !empty($entry['expires_at'])
                && (int) $entry['expires_at'] > $now
            ) {
                $valid[] = $entry;
            }
        }

        return $valid;
    }

    /**
     * Whether the current PHP runtime can execute the bundled library.
     * FreeScout supports PHP 7.1+, the WebAuthn ceremonies need OpenSSL.
     *
     * @return bool
     */
    public static function isRuntimeSupported()
    {
        return function_exists('openssl_verify');
    }
}
