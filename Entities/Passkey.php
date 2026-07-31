<?php

namespace Modules\Passkeys\Entities;

use Illuminate\Database\Eloquent\Model;

class Passkey extends Model
{
    protected $table = 'passkeys';

    /**
     * Only the user-facing label is mass assignable. All security-relevant
     * attributes (user_id, credential data, counters) are set explicitly.
     *
     * @var array
     */
    protected $fillable = ['name'];

    /**
     * Attributes hidden from serialization so credential material never
     * leaks into JSON responses by accident.
     *
     * @var array
     */
    protected $hidden = ['credential_id', 'credential_id_hash', 'public_key', 'sign_count'];

    protected $dates = ['last_used_at'];

    public function user()
    {
        return $this->belongsTo('App\User');
    }

    /**
     * Find a passkey by its raw binary credential ID.
     *
     * @param string $rawCredentialId
     * @return Passkey|null
     */
    public static function findByRawCredentialId($rawCredentialId)
    {
        if (!is_string($rawCredentialId) || $rawCredentialId === '') {
            return null;
        }

        $passkey = self::where('credential_id_hash', hash('sha256', $rawCredentialId))->first();

        // The hash lookup is only an index shortcut - confirm the exact match.
        if ($passkey && hash_equals(base64_decode($passkey->credential_id), $rawCredentialId)) {
            return $passkey;
        }

        return null;
    }
}
