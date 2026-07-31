<?php
/**
 * Self-contained sanity test for the bundled WebAuthn library and the local
 * CBOR depth-limit hardening. No FreeScout, Laravel or Composer required -
 * just PHP (7.1+) with the OpenSSL extension.
 *
 *     php tests/webauthn_roundtrip.php
 *
 * It builds a synthetic ES256 authenticator and drives the exact ceremonies
 * the module performs (registration + login), then runs negative cases. Exits
 * non-zero if any assertion fails, so it is usable as a pre-commit / CI check.
 *
 * This does NOT test the Laravel-facade-dependent controller/service code
 * (challenge session storage, rate limiting, 2FA gating); see CLAUDE.md for
 * how that is verified.
 */

error_reporting(E_ALL);

$root = dirname(__DIR__);

require $root . '/Vendor/polyfill.php';
spl_autoload_register(function ($class) use ($root) {
    $prefix = 'lbuchs\\WebAuthn\\';
    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }
    $file = $root . '/Vendor/WebAuthn/src/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

use lbuchs\WebAuthn\WebAuthn;
use lbuchs\WebAuthn\CBOR\CborDecoder;

$failures = 0;
function check($label, $cond)
{
    global $failures;
    if ($cond) {
        echo "  PASS  " . $label . "\n";
    } else {
        echo "  FAIL  " . $label . "\n";
        $failures++;
    }
}

// --- helpers to emulate an authenticator -------------------------------------
function b64url($b)
{
    return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
}
function cbor_len($major, $len)
{
    if ($len < 24) {
        return chr(($major << 5) | $len);
    }
    if ($len < 256) {
        return chr(($major << 5) | 24) . chr($len);
    }
    if ($len < 65536) {
        return chr(($major << 5) | 25) . pack('n', $len);
    }
    return chr(($major << 5) | 26) . pack('N', $len);
}
function cbor_bytes($b)
{
    return cbor_len(2, strlen($b)) . $b;
}
function cbor_text($s)
{
    return cbor_len(3, strlen($s)) . $s;
}
function cbor_int($i)
{
    return $i >= 0 ? cbor_len(0, $i) : cbor_len(1, -1 - $i);
}
function cose_ec2($x, $y)
{
    $m = cbor_len(5, 5);
    $m .= cbor_int(1) . cbor_int(2);     // kty EC2
    $m .= cbor_int(3) . cbor_int(-7);    // alg ES256
    $m .= cbor_int(-1) . cbor_int(1);    // crv P-256
    $m .= cbor_int(-2) . cbor_bytes($x);
    $m .= cbor_int(-3) . cbor_bytes($y);
    return $m;
}

$rpId = 'help.example.com';
$origin = 'https://help.example.com';

echo "WebAuthn round-trip\n";

// 1) server issues a registration challenge
$w = new WebAuthn('Test RP', $rpId, array('none'), true);
$w->getCreateArgs('42', 'agent@example.com', 'Agent', 60, 'required', 'required', null, array());
$regChallenge = $w->getChallenge()->getBinaryString();

// 2) authenticator creates a credential
$pkey = openssl_pkey_new(array('private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'));
$d = openssl_pkey_get_details($pkey);
$x = str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT);
$y = str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT);
$credId = random_bytes(32);
$rpIdHash = hash('sha256', $rpId, true);
$authData = $rpIdHash . chr(0x01 | 0x04 | 0x40) . pack('N', 0)
    . str_repeat("\0", 16) . pack('n', strlen($credId)) . $credId . cose_ec2($x, $y);
$att = cbor_len(5, 3) . cbor_text('fmt') . cbor_text('none')
    . cbor_text('attStmt') . cbor_len(5, 0)
    . cbor_text('authData') . cbor_bytes($authData);
$clientDataCreate = json_encode(array('type' => 'webauthn.create', 'challenge' => b64url($regChallenge), 'origin' => $origin), JSON_UNESCAPED_SLASHES);

// 3) server verifies registration
$data = (new WebAuthn('Test RP', $rpId, array('none'), true))
    ->processCreate($clientDataCreate, $att, $regChallenge, true, true);
check('registration returns matching credential id', hash_equals($data->credentialId, $credId));
check('registration returns a PEM public key', strpos($data->credentialPublicKey, 'PUBLIC KEY') !== false);
$pubKey = $data->credentialPublicKey;
$counter = is_int($data->signatureCounter) ? $data->signatureCounter : 0;

// 4) server issues a login challenge
$wl = new WebAuthn('Test RP', $rpId, array('none'), true);
$wl->getGetArgs(array(), 60, true, true, true, true, true, 'required');
$loginChallenge = $wl->getChallenge()->getBinaryString();

// 5) authenticator signs the assertion
$authDataGet = $rpIdHash . chr(0x01 | 0x04) . pack('N', 0);
$clientDataGet = json_encode(array('type' => 'webauthn.get', 'challenge' => b64url($loginChallenge), 'origin' => $origin), JSON_UNESCAPED_SLASHES);
openssl_sign($authDataGet . hash('sha256', $clientDataGet, true), $sig, $pkey, OPENSSL_ALGO_SHA256);

// 6) server verifies the assertion
$ok = (new WebAuthn('Test RP', $rpId, array('none'), true))
    ->processGet($clientDataGet, $authDataGet, $sig, $pubKey, $loginChallenge, $counter, true, true);
check('login assertion verifies', $ok === true);

echo "Negative cases (must be rejected)\n";
$reject = function ($label, callable $fn) {
    try {
        $fn();
        check($label, false);
    } catch (\Throwable $e) {
        check($label, true);
    }
};
$reject('wrong challenge rejected', function () use ($rpId, $clientDataGet, $authDataGet, $sig, $pubKey, $counter) {
    (new WebAuthn('Test RP', $rpId, array('none'), true))->processGet($clientDataGet, $authDataGet, $sig, $pubKey, random_bytes(32), $counter, true, true);
});
$reject('tampered signature rejected', function () use ($rpId, $clientDataGet, $authDataGet, $sig, $pubKey, $loginChallenge, $counter) {
    $bad = $sig;
    $bad[strlen($bad) - 1] = chr(ord($bad[strlen($bad) - 1]) ^ 0xFF);
    (new WebAuthn('Test RP', $rpId, array('none'), true))->processGet($clientDataGet, $authDataGet, $bad, $pubKey, $loginChallenge, $counter, true, true);
});
$reject('wrong origin rejected', function () use ($rpId, $rpIdHash, $authDataGet, $pubKey, $loginChallenge, $counter, $pkey) {
    $cd = json_encode(array('type' => 'webauthn.get', 'challenge' => b64url($loginChallenge), 'origin' => 'https://evil.com'), JSON_UNESCAPED_SLASHES);
    openssl_sign($authDataGet . hash('sha256', $cd, true), $s2, $pkey, OPENSSL_ALGO_SHA256);
    (new WebAuthn('Test RP', $rpId, array('none'), true))->processGet($cd, $authDataGet, $s2, $pubKey, $loginChallenge, $counter, true, true);
});

echo "CBOR depth guard (local hardening)\n";
$shallow = CborDecoder::decode("\xA1\x01\x61a"); // {1: "a"}
check('shallow CBOR still decodes', isset($shallow[1]) && $shallow[1] === 'a');
$reject('deeply nested CBOR rejected (not fatal)', function () {
    CborDecoder::decode(str_repeat("\xC0", 200) . "\x00");
});

echo "\n";
if ($failures === 0) {
    echo "ALL PASSED\n";
    exit(0);
}
echo $failures . " FAILURE(S)\n";
exit(1);
