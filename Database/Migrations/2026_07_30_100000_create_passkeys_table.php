<?php

use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Migrations\Migration;

class CreatePasskeysTable extends Migration
{
    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('passkeys', function (Blueprint $table) {
            $table->increments('id');
            $table->unsignedInteger('user_id')->index();
            // User-chosen label for the credential.
            $table->string('name', 64);
            // Base64url-encoded credential ID (spec allows up to 1023 bytes raw,
            // so it is stored as TEXT and looked up via the fixed-length hash below).
            $table->text('credential_id');
            // SHA-256 (hex) of the raw binary credential ID. Fixed length, safe to
            // index uniquely on any MySQL/MariaDB/PostgreSQL version.
            $table->string('credential_id_hash', 64)->unique();
            // COSE public key converted to PEM.
            $table->text('public_key');
            $table->unsignedInteger('sign_count')->default(0);
            // JSON array of authenticator transports reported by the browser.
            $table->string('transports', 255)->nullable();
            $table->string('aaguid', 36)->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::dropIfExists('passkeys');
    }
}
