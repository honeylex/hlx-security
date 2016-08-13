<?php

namespace Hlx\Security\Service\Provisioner;

use Auryn\Injector;
use Gigablah\Silex\OAuth\OAuthServiceProvider;
use Hlx\Security\Authenticator\OauthAuthenticator;
use Hlx\Security\Authenticator\TokenAuthenticator;
use Hlx\Security\EventListener\OauthInfoListener;
use Hlx\Security\Locale\SessionLocaleListener;
use Hlx\Security\Locale\UserLocaleListener;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\FrameworkBinding\Silex\Service\Provisioner\SilexServiceProvisioner;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Config\SettingsInterface;
use Honeybee\ServiceDefinitionInterface;
use Pimple\Container;
use Silex\Api\EventListenerProviderInterface;
use Silex\Provider\RememberMeServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

class UserServiceProvisioner extends SilexServiceProvisioner implements EventListenerProviderInterface
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
        $crate_settings = $crate->getSettings();

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
            return new TokenAuthenticator;
        };

        // oauth token authenticator
        $app['hlx.security.oauth_authenticator'] = function ($app) {
            return new OauthAuthenticator($app['security.token_storage'], $app['security.trust_resolver']);
        };

        // register oauth services
        $oauth_services = [];
        if ($oauth_settings = $crate_settings->get('oauth')) {
            if ($facebook_settings = $oauth_settings->get('facebook')) {
                $oauth_services['Facebook'] = [
                    'key' => (string) $facebook_settings->get('app_key'),
                    'secret' => (string) $facebook_settings->get('app_secret'),
                    'scope' => (array) $facebook_settings->get('scope'),
                    'user_endpoint' => sprintf(
                        'https://graph.facebook.com/me?fields=%s',
                        implode(',', (array) $facebook_settings->get('fields', [ 'id', 'name' , 'email' ]))
                    )
                ];
            }
        }

        $app->register(
            new OAuthServiceProvider,
            [
                'oauth.services' => $oauth_services,
                'oauth.user_info_listener' => function ($app) use ($oauth_settings) {
                    return new OauthInfoListener($app['oauth'], $app['oauth.services'], $oauth_settings);
                }
            ]
        );

        // setup firewalls
        $custom_firewalls = $crate_settings->get('firewalls', new Settings)->toArray();
        $oauth_firewalls = $oauth_settings ? [
            'oauth' => [
                // provide security context to default firewall
                'context' => $oauth_settings->get('context', 'default'),
                'pattern' => "^$routing_prefix/auth/",
                'anonymous' => true,
                'oauth' => [
                    'login_path' => "$routing_prefix/auth/{service}",
                    'callback_path' => "$routing_prefix/auth/{service}/callback",
                    'check_path' => "$routing_prefix/auth/{service}/check",
                    'failure_path' => "$routing_prefix/login",
                    'default_target_path' => "$routing_prefix/user/list",
                    'with_csrf' => true
                ],
                'users' => $app[$serviceKey]
            ]
        ] : [];

        $app->register(
            new SecurityServiceProvider,
            [
                'security.default_encoder' => $app[$serviceKey],
                'security.firewalls' => array_merge(
                    // @todo need better firewall building and merge
                    $custom_firewalls,
                    $oauth_firewalls,
                    [
                        'dev' => [
                            'pattern' => '^/_(profiler|wdt)/',
                            'security' => false
                        ],
                        'login' => [ 'pattern' => "^$routing_prefix/login$" ],
                        'registration' => [ 'pattern' => "^$routing_prefix/registration$" ],
                        'verification' => [ 'pattern' => "^$routing_prefix/verify$" ],
                        'set_password' => [ 'pattern' => "^$routing_prefix/set_password$" ],
                        'forgot_password' => [ 'pattern' => "^$routing_prefix/forgot_password$" ],
                        'home' => [
                            'pattern' => '^/$',
                            'anonymous' => true
                        ],
                        'default' => [
                            'pattern' => "^.*$",
                            'anonymous' => false,
                            'guard' => [
                                'authenticators' => [
                                    'hlx.security.oauth_authenticator'
                                ]
                            ],
                            'form' => [
                                'login_path' => "$routing_prefix/login",
                                'check_path' => "$routing_prefix/login_check",
                                'default_target_path' => "$routing_prefix/user/list"
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
                    [ '^/user', 'ROLE_ADMIN' ],
                    [ '^/auth', 'ROLE_USER' ]
                ],
                'security.role_hierarchy' => [
                    'administrator' => [ 'ROLE_ADMIN', 'ROLE_USER' ],
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

    public function subscribe(Container $app, EventDispatcherInterface $dispatcher)
    {
        if (isset($app['session'])) {
            $dispatcher->addSubscriber(new SessionLocaleListener);
            $dispatcher->addSubscriber(new UserLocaleListener($app['session']));
        }
    }
}
