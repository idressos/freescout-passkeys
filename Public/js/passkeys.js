/**
 * Passkeys module for FreeScout - client side.
 *
 * Self-contained (no jQuery or other dependencies) and CSP-friendly: it
 * boots itself from the JSON config embedded in the page (a non-executable
 * <script type="application/json"> block), so no inline JS is required.
 * All binary WebAuthn fields travel as base64url strings.
 */
(function () {
    'use strict';

    var abortCtrl = null;

    function bufToB64u(buf) {
        var bytes = new Uint8Array(buf);
        var str = '';
        for (var i = 0; i < bytes.length; i++) {
            str += String.fromCharCode(bytes[i]);
        }
        return window.btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function b64uToBuf(b64u) {
        var b64 = String(b64u).replace(/-/g, '+').replace(/_/g, '/');
        while (b64.length % 4) {
            b64 += '=';
        }
        var str = window.atob(b64);
        var bytes = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function isSupported() {
        return !!(window.PublicKeyCredential
            && navigator.credentials
            && typeof navigator.credentials.create === 'function'
            && typeof navigator.credentials.get === 'function'
            && window.isSecureContext !== false);
    }

    function post(url, csrf, data) {
        return window.fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-CSRF-TOKEN': csrf,
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify(data || {})
        }).then(function (response) {
            return response.json().catch(function () {
                return {};
            }).then(function (json) {
                if (!response.ok || json.status !== 'success') {
                    var err = new Error(json.message || ('HTTP ' + response.status));
                    err.handled = !!json.message;
                    throw err;
                }
                return json;
            });
        });
    }

    // Convert the base64url-encoded fields of the server-provided
    // PublicKeyCredential options to ArrayBuffers.
    function decodeCreateOptions(publicKey) {
        publicKey.challenge = b64uToBuf(publicKey.challenge);
        publicKey.user.id = b64uToBuf(publicKey.user.id);
        var i;
        if (publicKey.excludeCredentials) {
            for (i = 0; i < publicKey.excludeCredentials.length; i++) {
                publicKey.excludeCredentials[i].id = b64uToBuf(publicKey.excludeCredentials[i].id);
            }
        }
        return publicKey;
    }

    function decodeGetOptions(publicKey) {
        publicKey.challenge = b64uToBuf(publicKey.challenge);
        var i;
        if (publicKey.allowCredentials) {
            for (i = 0; i < publicKey.allowCredentials.length; i++) {
                publicKey.allowCredentials[i].id = b64uToBuf(publicKey.allowCredentials[i].id);
            }
        }
        return publicKey;
    }

    function showAlert(el, message, type) {
        if (!el) {
            window.alert(message);
            return;
        }
        el.textContent = message;
        el.className = 'alert ' + (type === 'success' ? 'alert-success' : 'alert-danger');
        el.style.display = 'block';
    }

    function hideAlert(el) {
        if (el) {
            el.style.display = 'none';
        }
    }

    function errorMessage(e, i18n) {
        if (e && e.handled) {
            return e.message;
        }
        if (e && (e.name === 'NotAllowedError' || e.name === 'AbortError')) {
            return i18n.cancelled;
        }
        if (e && e.name === 'InvalidStateError') {
            return i18n.already_registered;
        }
        return i18n.failed;
    }

    /**
     * Passkey management on the user's profile page.
     */
    function initProfile(opts) {
        var button = document.getElementById('passkeys-register-btn');
        var nameInput = document.getElementById('passkeys-register-name');
        var alertEl = document.getElementById('passkeys-alert');

        // Rename: ask for the new name before submitting the form.
        var renameForms = document.querySelectorAll('.passkeys-rename-form');
        var i;
        for (i = 0; i < renameForms.length; i++) {
            (function (form) {
                form.addEventListener('submit', function (e) {
                    var name = window.prompt(opts.i18n.rename_prompt, form.getAttribute('data-name') || '');
                    if (name === null || !name.replace(/\s/g, '').length) {
                        e.preventDefault();
                        return;
                    }
                    form.querySelector('input[name="name"]').value = name;
                });
            })(renameForms[i]);
        }

        // Delete: confirm before submitting the form.
        var deleteForms = document.querySelectorAll('.passkeys-delete-form');
        for (i = 0; i < deleteForms.length; i++) {
            (function (form) {
                form.addEventListener('submit', function (e) {
                    if (!window.confirm(opts.i18n.delete_confirm)) {
                        e.preventDefault();
                    }
                });
            })(deleteForms[i]);
        }

        if (!button) {
            return;
        }

        if (!isSupported()) {
            button.disabled = true;
            if (nameInput) {
                nameInput.disabled = true;
            }
            showAlert(alertEl, opts.i18n.not_supported, 'danger');
            return;
        }

        button.addEventListener('click', function (e) {
            e.preventDefault();
            hideAlert(alertEl);
            button.disabled = true;

            post(opts.urls.registerOptions, opts.csrf, {})
                .then(function (json) {
                    return navigator.credentials.create({
                        publicKey: decodeCreateOptions(json.options.publicKey)
                    });
                })
                .then(function (credential) {
                    var transports = [];
                    if (credential.response.getTransports) {
                        try {
                            transports = credential.response.getTransports();
                        } catch (err) {
                            transports = [];
                        }
                    }
                    return post(opts.urls.registerVerify, opts.csrf, {
                        name: nameInput ? nameInput.value : '',
                        clientDataJSON: bufToB64u(credential.response.clientDataJSON),
                        attestationObject: bufToB64u(credential.response.attestationObject),
                        transports: transports
                    });
                })
                .then(function () {
                    window.location.reload();
                })
                .catch(function (err) {
                    button.disabled = false;
                    showAlert(alertEl, errorMessage(err, opts.i18n), 'danger');
                });
        });
    }

    function finishLogin(opts, credential) {
        return post(opts.urls.loginVerify, opts.csrf, {
            id: bufToB64u(credential.rawId),
            clientDataJSON: bufToB64u(credential.response.clientDataJSON),
            authenticatorData: bufToB64u(credential.response.authenticatorData),
            signature: bufToB64u(credential.response.signature),
            userHandle: credential.response.userHandle
                ? bufToB64u(credential.response.userHandle)
                : null
        }).then(function (json) {
            // The admin may require a second factor after the passkey.
            if (json.two_factor_required) {
                showTwoFactor(opts);
                return;
            }
            window.location.href = json.redirect;
        });
    }

    // Reveal the second-factor prompt and wire its submission.
    function showTwoFactor(opts) {
        var block = document.getElementById('passkeys-2fa-block');
        var input = document.getElementById('passkeys-2fa-code');
        var submit = document.getElementById('passkeys-2fa-submit');
        var loginBtn = document.getElementById('passkeys-login-btn');
        var alertEl = document.getElementById('passkeys-login-alert');

        if (!block || !input || !submit) {
            showAlert(alertEl, opts.i18n.twofa_prompt, 'success');
            return;
        }

        if (loginBtn) {
            loginBtn.style.display = 'none';
        }
        hideAlert(alertEl);
        block.style.display = '';
        input.focus();

        if (submit.getAttribute('data-wired') === '1') {
            return;
        }
        submit.setAttribute('data-wired', '1');

        var verify = function () {
            var code = input.value;
            if (!code || !code.replace(/\s/g, '').length) {
                return;
            }
            submit.disabled = true;
            hideAlert(alertEl);

            post(opts.urls.loginTwoFactor, opts.csrf, { code: code })
                .then(function (json) {
                    window.location.href = json.redirect;
                })
                .catch(function (err) {
                    submit.disabled = false;
                    showAlert(alertEl, errorMessage(err, opts.i18n), 'danger');
                });
        };

        submit.addEventListener('click', function (e) {
            e.preventDefault();
            verify();
        });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'Enter' || e.keyCode === 13) {
                e.preventDefault();
                verify();
            }
        });
    }

    function requestAssertion(opts, conditional) {
        if (abortCtrl) {
            abortCtrl.abort();
            abortCtrl = null;
        }

        return post(opts.urls.loginOptions, opts.csrf, {})
            .then(function (json) {
                var request = {
                    publicKey: decodeGetOptions(json.options.publicKey)
                };
                if (conditional) {
                    request.mediation = 'conditional';
                    if (window.AbortController) {
                        abortCtrl = new AbortController();
                        request.signal = abortCtrl.signal;
                    }
                }
                return navigator.credentials.get(request);
            })
            .then(function (credential) {
                return finishLogin(opts, credential);
            });
    }

    /**
     * "Login with a passkey" button on the login page.
     */
    function initLogin(opts) {
        var button = document.getElementById('passkeys-login-btn');
        var alertEl = document.getElementById('passkeys-login-alert');

        if (!button || !isSupported()) {
            return;
        }

        button.style.display = '';

        // Place the passkey button on the same row as the Login / Forgot
        // buttons, justified to the far right, instead of full-width below the
        // form. Only passkey-capable browsers reach this code, so the login
        // page layout is untouched for everyone else.
        try {
            var submitBtn = document.querySelector('form button[type="submit"]');
            if (submitBtn && submitBtn.parentNode) {
                submitBtn.parentNode.className += ' passkeys-login-row';
                submitBtn.parentNode.appendChild(button);
            }
        } catch (e) {
            // Fall back to the button's default position below the form.
        }

        button.addEventListener('click', function (e) {
            e.preventDefault();
            hideAlert(alertEl);
            button.disabled = true;

            requestAssertion(opts, false)
                .catch(function (err) {
                    button.disabled = false;
                    showAlert(alertEl, errorMessage(err, opts.i18n), 'danger');
                });
        });

        // Progressive enhancement: offer passkeys via the browser's own
        // autofill UI (conditional mediation) when available.
        if (window.PublicKeyCredential
            && typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function') {
            window.PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
                if (!available) {
                    return;
                }
                var emailField = document.querySelector('input[name="email"]');
                if (emailField) {
                    var autocomplete = emailField.getAttribute('autocomplete') || 'username';
                    if (autocomplete.indexOf('webauthn') === -1) {
                        emailField.setAttribute('autocomplete', autocomplete + ' webauthn');
                    }
                }
                requestAssertion(opts, true).catch(function () {
                    // Conditional requests are aborted/dismissed routinely - stay quiet.
                });
            }).catch(function () {
                // Ignore detection errors.
            });
        }
    }

    function boot() {
        var configEl = document.getElementById('passkeys-config');

        if (!configEl) {
            return;
        }

        var config;
        try {
            config = JSON.parse(configEl.textContent);
        } catch (e) {
            return;
        }

        if (config.page === 'profile') {
            initProfile(config);
        } else if (config.page === 'login') {
            initLogin(config);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
