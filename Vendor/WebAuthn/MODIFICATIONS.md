# Modifications to the bundled lbuchs/WebAuthn library

This is a copy of [lbuchs/WebAuthn](https://github.com/lbuchs/WebAuthn)
**v2.2.0** (MIT, see `LICENSE`), bundled with the FreeScout Passkeys module.

The library is included **unmodified** except for the single change below,
made for defense-in-depth. The change is clearly marked in the source with
`Local modification (FreeScout Passkeys)` comments.

## `src/CBOR/CborDecoder.php` — recursion-depth limit

Upstream places no bound on CBOR nesting depth, so a maliciously nested
payload can drive the recursive parser into deep recursion / large
allocations. A `MAX_DEPTH` constant (32 — far above anything a real WebAuthn
message uses) and a `$depth` parameter were added to `_parseItem()`,
`_parseItemData()`, `_parseArray()` and `_parseMap()`; parsing throws a
`WebAuthnException` once the limit is exceeded. All added parameters default
to `0`, so the public API is unchanged.

Nothing else in the library has been altered.
