<?php

namespace Hlx\Security\Service\Provisioner;

use Auryn\Injector;
use Gigablah\Silex\OAuth\OAuthServiceProvider;
use Hlx\Security\Authenticator\OauthAuthenticator;
use Hlx\Security\Authenticator\TokenAuthenticator;
use Hlx\Security\EventListener\OauthInfoListener;
use Hlx\Security\EventListener\SessionLocaleListener;
use Hlx\Security\EventListener\UserLocaleListener;
use Hlx\Security\EventListener\UserLoginListener;
use Hlx\Security\EventListener\UserLogoutListener;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\FrameworkBinding\Silex\Service\Provisioner\ProvisionerInterface;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Config\SettingsInterface;
use Honeybee\ServiceDefinitionInterface;
use Pimple\Container;
use Silex\Api\EventListenerProviderInterface;
use Silex\Provider\RememberMeServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserServiceProvisioner implements ProvisionerInterface, EventListenerProviderInterface
{
    public function provision(
        Container $app,
        Injector $injector,
        ConfigProviderInterface $configProvider,
        ServiceDefinitionInterface $serviceDefinition,
        SettingsInterface $provisionerSettings
    ) {
        $service = $serviceDefinition->getClass();
        $crate = $configProvider->getCrateMap()->getItem('hlx.security');
        $crateSettings = $crate->getSettings();

        // allow override of routing prefix from crate settings
        $routingPrefix = $crate->getRoutingPrefix();
        if ($routingPrefix === '/') {
            $routingPrefix = '';
        }

        // Make the user service upfront for the security provider
        $userService = $injector
            ->share($service)
            ->alias(UserProviderInterface::CLASS, $service)
            ->make($service);

        // logout handler - 'default' matching firewall name
        $app['security.authentication.logout_handler.default'] = function ($app) use ($injector) {
            return $injector->share(UserLogoutListener::CLASS)->make(
                UserLogoutListener::CLASS,
                [ ':targetUrl' => $app['security.firewalls']['default']['logout']['target_url'] ]
            );
        };

        // login success handler - 'default' matching firewall name
        $app['security.authentication.success_handler.default'] = function ($app) use ($injector) {
            return $injector->share(UserLoginListener::CLASS)->make(
                UserLoginListener::CLASS,
                [ ':options' => $app['security.firewalls']['default']['form'] ]
            );
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
        if ($oauthSettings = $crateSettings->get('oauth')) {
            if ($facebook_settings = $oauthSettings->get('facebook')) {
                $oauth_services['Facebook'] = [
                    'key' => (string) $facebook_settings->get('app_key'),
                    'secret' => (string) $facebook_settings->get('app_secret'),
                    'scope' => (array) $facebook_settings->get('scope'),
                    'user_endpoint' => sprintf(
                        'https://graph.facebook.com/me?fields=%s',
                        implode(',', (array) $facebook_settings->get('fields', [ 'id', 'name', 'email' ]))
                    )
                ];
            }
        }

        $app->register(
            new OAuthServiceProvider,
            [
                'oauth.services' => $oauth_services,
                'oauth.user_info_listener' => function ($app) use ($oauthSettings) {
                    return new OauthInfoListener($app['oauth'], $app['oauth.services'], $oauthSettings);
                }
            ]
        );

        // setup firewalls
        $customFirewalls = $crateSettings->get('firewalls', new Settings)->toArray();
        $oauthFirewalls = $oauthSettings ? [
            'oauth' => [
                // provide security context to default firewall
                'context' => $oauthSettings->get('context', 'default'),
                'pattern' => "^$routingPrefix/auth/",
                'anonymous' => true,
                'oauth' => [
                    'login_path' => "$routingPrefix/auth/{service}",
                    'callback_path' => "$routingPrefix/auth/{service}/callback",
                    'check_path' => "$routingPrefix/auth/{service}/check",
                    'failure_path' => 'hlx.security.login',
                    'default_target_path' => 'home',
                    'with_csrf' => true
                ],
                'users' => $userService
            ]
        ] : [];

        $app->register(
            new SecurityServiceProvider,
            [
                'security.default_encoder' => $userService,
                'security.firewalls' => array_merge(
                    $oauthFirewalls,
                    array_replace_recursive(
                        [
                            'dev' => [
                                'pattern' => '^/_(profiler|wdt)/',
                                'security' => false
                            ],
                            'default' => [
                                'pattern' => "^.*$",
                                'anonymous' => true,
                                'form' => [
                                    'login_path' => 'hlx.security.login',
                                    'check_path' => 'hlx.security.login.check',
                                    'default_target_path' => '/'
                                ],
                                'logout' => [
                                    'logout_path' => "$routingPrefix/logout",
                                    'target_url' => '/',
                                    'invalidate_session' => true,
                                    'with_csrf' => true
                                ],
                                'remember_me' => [
                                    'name' => 'HLX_SECURITY'
                                ],
                                'users' => $userService
                            ]
                        ],
                        $customFirewalls
                    )
                ),
                'security.access_rules' => array_merge(
                    $crateSettings->get('access_rules', new Settings)->toArray(),
                    [
                        [ "^$routingPrefix/login$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
                        [ "^$routingPrefix/password/(set|forgot)$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
                        [ "^$routingPrefix/registration$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
                        [ "^$routingPrefix/verify$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
                        [ "^$routingPrefix/user", 'ROLE_ADMIN' ],
                        [ "^$routingPrefix/auth", 'ROLE_USER' ]
                    ]
                ),
                'security.role_hierarchy' => array_merge(
                    [
                        'administrator' => [ 'ROLE_ADMIN', 'ROLE_USER', 'ROLE_ALLOWED_TO_SWITCH' ],
                        'user' => [ 'ROLE_USER' ]
                    ],
                    $crateSettings->get('role_hierarchy', new Settings)->toArray()
                )
            ]
        );

        // register after SecurityServiceProvider
        if ($provisionerSettings->get('stateless', false) !== true) {
            $app->register(new SessionServiceProvider);
            $app->register(new RememberMeServiceProvider);
        }

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
