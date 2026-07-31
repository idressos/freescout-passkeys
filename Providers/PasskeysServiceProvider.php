<?php

namespace Modules\Passkeys\Providers;

use Illuminate\Support\ServiceProvider;

// Module alias.
define('PASSKEYS_MODULE', 'passkeys');

class PasskeysServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boot the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerConfig();
        $this->registerViews();
        $this->loadMigrationsFrom(__DIR__.'/../Database/Migrations');
        $this->hooks();
        $this->registerUserCleanup();
    }

    /**
     * Remove a user's passkeys when their account is deleted, so a credential
     * can never outlive its owner or be re-bound to a recycled user id.
     * FreeScout soft-deletes users (status = STATUS_DELETED via an update),
     * so both the "updated to deleted" and hard "deleted" cases are covered.
     */
    protected function registerUserCleanup()
    {
        $purge = function ($user) {
            try {
                \Modules\Passkeys\Entities\Passkey::where('user_id', $user->id)->delete();
            } catch (\Throwable $e) {
                // Never let cleanup break user administration.
            }
        };

        \App\User::updated(function ($user) use ($purge) {
            if ((int) $user->status === \App\User::STATUS_DELETED) {
                $purge($user);
            }
        });

        \App\User::deleted($purge);
    }

    /**
     * Module hooks.
     */
    public function hooks()
    {
        // Module CSS - only on the pages that use passkeys.
        \Eventy::addFilter('stylesheets', function ($styles) {
            if ($this->isPasskeysPage()) {
                $path = \Module::getPublicPath(PASSKEYS_MODULE).'/css/passkeys.css';
                if (file_exists(public_path($path))) {
                    $styles[] = $path;
                }
            }

            return $styles;
        });

        // Module JS (external file - compatible with FreeScout's CSP).
        \Eventy::addFilter('javascripts', function ($javascripts) {
            if ($this->isPasskeysPage()) {
                $path = \Module::getPublicPath(PASSKEYS_MODULE).'/js/passkeys.js';
                if (file_exists(public_path($path))) {
                    $javascripts[] = $path;
                }
            }

            return $javascripts;
        });

        // "Login with a passkey" button below the login form.
        // Any error here must never break the login page.
        \Eventy::addAction('login_form.after', function () {
            try {
                echo \View::make('passkeys::login_button')->render();
            } catch (\Exception $e) {
                \Helper::logException($e, '[Passkeys] ');
            }
        });

        // "Passkeys" item in the profile sidebar menu - shown only to the
        // profile's own user, since passkeys can only be self-managed.
        \Eventy::addAction('user.profile.menu.after_profile', function ($user) {
            try {
                if (auth()->user() && (int)$user->id === (int)auth()->user()->id) {
                    echo \View::make('passkeys::partials/profile_menu', ['user' => $user])->render();
                }
            } catch (\Exception $e) {
                \Helper::logException($e, '[Passkeys] ');
            }
        }, 20, 1);

        $this->settingsHooks();
    }

    /**
     * Admin settings section (Manage » Settings » Passkeys).
     */
    protected function settingsHooks()
    {
        \Eventy::addFilter('settings.sections', function ($sections) {
            $sections['passkeys'] = ['title' => __('Passkeys'), 'icon' => 'lock', 'order' => 650];

            return $sections;
        }, 40);

        \Eventy::addFilter('settings.section_settings', function ($settings, $section) {
            if ($section !== 'passkeys') {
                return $settings;
            }

            $settings['passkeys.bypass_2fa'] = \Option::get('passkeys.bypass_2fa', config('passkeys.bypass_2fa', false));

            return $settings;
        }, 40, 2);

        \Eventy::addFilter('settings.section_params', function ($params, $section) {
            if ($section !== 'passkeys') {
                return $params;
            }

            // No 'env' key -> the value is persisted via \Option::set().
            $params['settings'] = [
                'passkeys.bypass_2fa' => ['default' => false],
            ];

            return $params;
        }, 40, 2);

        \Eventy::addFilter('settings.view', function ($view, $section) {
            return $section === 'passkeys' ? 'passkeys::settings' : $view;
        }, 40, 2);
    }

    /**
     * Pages on which the module's assets are needed.
     *
     * @return bool
     */
    protected function isPasskeysPage()
    {
        return \Route::is('login') || \Route::is('passkeys.profile');
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerTranslations();
    }

    /**
     * Register config.
     *
     * @return void
     */
    protected function registerConfig()
    {
        $this->publishes([
            __DIR__.'/../Config/config.php' => config_path('passkeys.php'),
        ], 'config');
        $this->mergeConfigFrom(
            __DIR__.'/../Config/config.php', 'passkeys'
        );
    }

    /**
     * Register views.
     *
     * @return void
     */
    public function registerViews()
    {
        $viewPath = resource_path('views/modules/passkeys');

        $sourcePath = __DIR__.'/../Resources/views';

        $this->publishes([
            $sourcePath => $viewPath,
        ], 'views');

        $this->loadViewsFrom(array_merge(array_map(function ($path) {
            return $path.'/modules/passkeys';
        }, \Config::get('view.paths')), [$sourcePath]), 'passkeys');
    }

    /**
     * Register translations.
     *
     * @return void
     */
    public function registerTranslations()
    {
        $this->loadJsonTranslationsFrom(__DIR__.'/../Resources/lang');
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return [];
    }
}
