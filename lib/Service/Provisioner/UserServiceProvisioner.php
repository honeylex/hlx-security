<?php

namespace Hlx\Security\Service\Provisioner;

use Auryn\Injector;
use Gigablah\Silex\OAuth\OAuthServiceProvider;
use Hlx\Security\Authenticator\OauthAuthenticator;
use Hlx\Security\Authenticator\TokenAuthenticator;
use Hlx\Security\EventListener\OauthInfoListener;
use Hlx\Security\EventListener\UserLocaleListener;
use Hlx\Security\EventListener\UserLoginListener;
use Hlx\Security\EventListener\UserLogoutListener;
use Hlx\Security\Voter\OwnershipVoter;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\FrameworkBinding\Silex\Service\Provisioner\ProvisionerInterface;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Config\SettingsInterface;
use Honeybee\ServiceDefinitionInterface;
use Pimple\Container;
use Silex\Api\EventListenerProviderInterface;
use Silex\Provider\RememberMeServiceProvider;
use Silex\Provider\SecurityServiceProvider;
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
        $crateSettings = $configProvider->getCrateSettings('hlx.security');

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

        // setup firewalls
        $devFirewall = $app['debug'] ? [
            'dev' => [
                'pattern' => '^/_(profiler|wdt)/',
                'security' => false
            ]
        ] : [];

        $securityFirewalls = array_replace_recursive(
            $devFirewall,
            [
                'default' => [
                    'pattern' => "^.*$",
                    'anonymous' => true,
                    'form' => [
                        'login_path' => "$routingPrefix/login",
                        'check_path' => "$routingPrefix/login/check",
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
            $crateSettings->get('firewalls', new Settings)->toArray()
        );

        // register oauth services
        if ($oauthSettings = $crateSettings->get('oauth')) {
            $oauthServices = [];
            if ($facebookSettings = $oauthSettings->get('facebook')) {
                if ($facebookSettings->get('enabled')) {
                    $oauthServices['Facebook'] = [
                        'key' => (string) $facebookSettings->get('app_key'),
                        'secret' => (string) $facebookSettings->get('app_secret'),
                        'scope' => (array) $facebookSettings->get('scope'),
                        'user_endpoint' => sprintf(
                            'https://graph.facebook.com/me?fields=%s',
                            implode(',', (array) $facebookSettings->get('fields', [ 'id', 'name', 'email' ]))
                        )
                    ];
                }
            }

            if (!empty($oauthServices)) {
                // merge oauth firewalls
                $securityFirewalls = array_merge(
                    [
                        'oauth' => [
                            // provide security context to specific firewall
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
                    ],
                    $securityFirewalls
                );

                $app->register(
                    new OAuthServiceProvider,
                    [
                        'oauth.services' => $oauthServices,
                        'oauth.user_info_listener' => function ($app) use ($oauthSettings) {
                            return new OauthInfoListener($app['oauth'], $app['oauth.services'], $oauthSettings);
                        }
                    ]
                );
            }
        }

        // setup roles and rules
        $roleHierarchy =  [
            'ROLE_ADMIN' => [ 'ROLE_USER', 'ROLE_ALLOWED_TO_SWITCH' ],
            'administrator' => [ 'ROLE_ADMIN' ],
            'user' => [ 'ROLE_USER' ]
        ];

        $accessRules = [
            [ "^$routingPrefix/login$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
            [ "^$routingPrefix/password/(set|forgot)$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
            [ "^$routingPrefix/registration$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
            [ "^$routingPrefix/verify$", 'IS_AUTHENTICATED_ANONYMOUSLY' ],
            [ "^$routingPrefix/users", 'ROLE_ADMIN' ],
            [ "^$routingPrefix/auth", 'ROLE_USER' ]
        ];

        if ($rolesSettings = $crateSettings->get('roles', new Settings)) {
            $roleHierarchy = array_merge(
                $roleHierarchy,
                $rolesSettings->get('role_hierarchy', new Settings)->toArray()
            );
            $accessRules = array_merge(
                $rolesSettings->get('access_rules', new Settings)->toArray(),
                $accessRules
            );
        }

        // Api setup
        if ($apiSettings = $crateSettings->get('api', new Settings)) {
            if ($apiSettings->get('enabled')) {
                $app['hlx.security.token_authenticator'] = function ($app) {
                    return new TokenAuthenticator;
                };
            }
        }

        // register the security service
        $app->register(
            new SecurityServiceProvider,
            [
                'security.default_encoder' => $userService,
                'security.firewalls' => $securityFirewalls,
                'security.access_rules' => $accessRules,
                'security.role_hierarchy' => $roleHierarchy
            ]
        );

        // register after SecurityServiceProvider
        $app->register(new RememberMeServiceProvider);

        $this->registerSecurityVoters($app, $injector, $crateSettings->get('voters', new Settings));
        $this->registerLogoutHandler($app, $injector);
        $this->registerLoginHandler($app, $injector);

        return $injector;
    }


    protected function registerLogoutHandler(Container $app, Injector $injector)
    {
        // logout handler - 'default' matching firewall name
        $app['security.authentication.logout_handler.default'] = function ($app) use ($injector) {
            return $injector->share(UserLogoutListener::CLASS)->make(
                UserLogoutListener::CLASS,
                [ ':targetUrl' => $app['security.firewalls']['default']['logout']['target_url'] ]
            );
        };
    }

    protected function registerLoginHandler(Container $app, Injector $injector)
    {
        // 'default' matching firewall name
        $app['security.authentication.success_handler.default'] = function ($app) use ($injector) {
            return $injector->share(UserLoginListener::CLASS)->make(
                UserLoginListener::CLASS,
                [ ':options' => $app['security.firewalls']['default']['form'] ]
            );
        };
    }

    protected function registerSecurityVoters(Container $app, Injector $injector, SettingsInterface $voterSettings)
    {
        $app['security.voters'] = $app->extend('security.voters', function ($voters) use ($injector, $voterSettings) {
            foreach ($voterSettings as $voter) {
                $voters[] = $injector->make($voter);
            }
            return $voters;
        });
    }

    public function subscribe(Container $app, EventDispatcherInterface $dispatcher)
    {
        if (isset($app['session'])) {
            $dispatcher->addSubscriber(new UserLocaleListener($app['session']));
        }
    }
}
