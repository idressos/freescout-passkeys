@extends('layouts.app')

@section('title_full', __('Passkeys').' - '.$user->getFullName())

@section('sidebar')
    @include('partials/sidebar_menu_toggle')
    @include('users/sidebar_menu')
@endsection

@section('content')
    <div class="section-heading">
        {{ __('Passkeys') }}
    </div>

    <div class="row-container form-container">
        <div class="col-xs-12">

            <p class="block-help passkeys-intro">
                {{ __('Passkeys let you sign in without a password, using your device screen lock (fingerprint, face, PIN), a hardware security key or a password manager.') }}
            </p>

            @if (!$is_https)
                <div class="alert alert-warning">
                    {{ __('Passkeys require the helpdesk to be served over HTTPS. Your APP_URL does not use HTTPS, so browsers will refuse to register or use passkeys.') }}
                </div>
            @endif

            @if (!$runtime_supported)
                <div class="alert alert-danger">
                    {{ __('Passkeys are not supported by the server configuration (the PHP OpenSSL extension is required).') }}
                </div>
            @endif

            <div id="passkeys-alert"></div>

            @if (count($passkeys))
                <table class="table passkeys-table">
                    <thead>
                        <tr>
                            <th>{{ __('Name') }}</th>
                            <th>{{ __('Added') }}</th>
                            <th>{{ __('Last used') }}</th>
                            <th>&nbsp;</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($passkeys as $passkey)
                            <tr>
                                <td>
                                    <strong>{{ $passkey->name }}</strong>
                                    @if ($passkey->transports && in_array('internal', json_decode($passkey->transports, true) ?: []))
                                        <span class="passkeys-muted">({{ __('this device') }})</span>
                                    @endif
                                </td>
                                <td>{{ App\User::dateFormat($passkey->created_at) }}</td>
                                <td>
                                    @if ($passkey->last_used_at)
                                        {{ App\User::dateFormat($passkey->last_used_at) }}
                                    @else
                                        <span class="passkeys-muted">{{ __('Never') }}</span>
                                    @endif
                                </td>
                                <td class="text-right">
                                    <form method="POST" action="{{ route('passkeys.rename', ['id' => $passkey->id]) }}" class="passkeys-rename-form" style="display:inline;" data-name="{{ $passkey->name }}">
                                        {{ csrf_field() }}
                                        <input type="hidden" name="name" value="" />
                                        <button type="submit" class="btn btn-link passkeys-rename-btn">{{ __('Rename') }}</button>
                                    </form>
                                    <form method="POST" action="{{ route('passkeys.delete', ['id' => $passkey->id]) }}" class="passkeys-delete-form" style="display:inline;">
                                        {{ csrf_field() }}
                                        <button type="submit" class="btn btn-link text-danger passkeys-delete-btn">{{ __('Delete') }}</button>
                                    </form>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            @else
                <p class="text-help margin-top">
                    {{ __('You have no passkeys yet.') }}
                </p>
            @endif

            <div class="passkeys-register-form">
                <div class="form-inline">
                    <input type="text" id="passkeys-register-name" class="form-control" maxlength="64" placeholder="{{ __('Passkey name (e.g. Work laptop)') }}" />
                    <button type="button" id="passkeys-register-btn" class="btn btn-primary" @if (!$runtime_supported) disabled @endif>
                        {{ __('Add passkey') }}
                    </button>
                </div>
            </div>

        </div>
    </div>

    @include('passkeys::partials/config', ['page' => 'profile'])
@endsection
