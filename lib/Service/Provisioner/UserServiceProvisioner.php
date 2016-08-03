<?php

namespace Hlx\Security\Service\Provisioner;

use Auryn\Injector;
use Hlx\Security\Service\TokenAuthenticator;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\FrameworkBinding\Silex\Service\Provisioner\SilexServiceProvisioner;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Config\SettingsInterface;
use Honeybee\ServiceDefinitionInterface;
use Pimple\Container;
use Silex\Provider\RememberMeServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;

class UserServiceProvisioner extends SilexServiceProvisioner
{
    public function provision(
        Container $app,
        Injector $injector,
        ConfigProviderInterface $configProvider,
        ServiceDefinitionInterface $serviceDefinition,
        SettingsInterface $provisionerSettings
    ) {
        $service = $serviceDefinition->getClass();
        $serviceKey = $provisionerSettings->get('app_key');
        $crate = $configProvider->getCrateMap()->getItem('hlx.security');
        $crate_settings = $crate->getManifest()->getSettings();

        // allow override of routing prefix from crate settings
        $routing_prefix = $crate->getRoutingPrefix();
        if ($routing_prefix === '/') {
            $routing_prefix = '';
        }

        // provide cookie settings from crate config
        $cookie_settings = $crate_settings->get('cookie', new Settings);

        // Make the user service upfront for the security provider
        $app[$serviceKey] = $injector->make($service);

        // logout handler registration - 'default' matching firewall name
        $app['security.authentication.logout_handler.default'] = function () use ($injector, $provisionerSettings) {
            return $injector->make($provisionerSettings->get('logout_handler'));
        };

        // api token authenticator
        $app['hlx.security.token_authenticator'] = function ($app) {
            return new TokenAuthenticator($app['security.encoder_factory']);
        };

        $app->register(
            new SecurityServiceProvider,
            [
                'security.default_encoder' => $app[$serviceKey],
                'security.firewalls' => array_merge(
                    // @todo consider better firewall building and merge
                    $crate_settings->get('firewalls', new Settings)->toArray(),
                    [
                        'login' => [ 'pattern' => "^$routing_prefix/login$" ],
                        'registration' => [ 'pattern' => "^$routing_prefix/registration$" ],
                        'password' => [ 'pattern' => "^$routing_prefix/password$" ],
                        'home' => [
                            'pattern' => '^/$',
                            'anonymous' => true
                        ],
                        'default' => [
                            'pattern' => "^.*$",
                            'anonymous' => false,
                            'guard' => [
                                'authenticators' => [
                                    'hlx.security.token_authenticator'
                                ]
                            ],
                            'form' => [
                                'login_path' => "$routing_prefix/login",
                                'check_path' => "$routing_prefix/login_check",
                                'default_target_path' => "$routing_prefix/user/list",
                            ],
                            'logout' => [
                                'logout_path' => "$routing_prefix/logout",
                                'invalidate_session' => true,
                                'with_csrf' => true
                            ],
                            'remember_me' => array_merge(
                                [ 'name' => 'HLX_SECURITY' ],
                                $cookie_settings->toArray()
                            ),
                            'users' => $app[$serviceKey]
                        ]
                    ]
                ),
                'security.access_rules' => [
                    [ '^/user', 'ROLE_ADMIN' ]
                ],
                'security.role_hierarchy' => [
                    'administrator' => [ 'ROLE_ADMIN' ],
                    'user' => [ 'ROLE_USER' ]
                ]
            ]
        );

        // register after SecurityServiceProvider
        if ($provisionerSettings->get('stateless', false) !== true) {
            $app->register(new SessionServiceProvider);
            $app->register(new RememberMeServiceProvider);
        }

        parent::provision($app, $injector, $configProvider, $serviceDefinition, $provisionerSettings);

        return $injector;
    }
}
