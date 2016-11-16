<?php

namespace Hlx\Security\Service\Provisioner;

use Auryn\Injector;
use Gigablah\Silex\OAuth\OAuthServiceProvider;
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

        // Define the user service and delegate upfront for the security provider
        $injector->share($service)->alias(UserProviderInterface::CLASS, $service);
        $userProviderDelegate = function () use ($injector, $service) {
            return $injector->make($service);
        };

        // setup firewalls
        $devFirewall = $app['debug'] ? [
            'development' => [
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
                    'users' => $userProviderDelegate
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
                            'pattern' => "^$routingPrefix/oauth/",
                            'anonymous' => true,
                            'oauth' => [
                                'login_path' => "$routingPrefix/oauth/{service}",
                                'callback_path' => "$routingPrefix/oauth/{service}/callback",
                                'check_path' => "$routingPrefix/oauth/{service}/check",
                                // @todo check the following are properly generated paths
                                'failure_path' => 'hlx.security.login',
                                'default_target_path' => 'home',
                                'with_csrf' => true
                            ],
                            'users' => $userProviderDelegate
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
        $accessRules = [];
        $roleHierarchy =  [
            'ROLE_ADMIN' => [ 'ROLE_USER', 'ROLE_ALLOWED_TO_SWITCH' ],
            'administrator' => [ 'ROLE_ADMIN' ],
            'user' => [ 'ROLE_USER' ]
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

        // register the security service
        $app->register(
            new SecurityServiceProvider,
            [
                'security.default_encoder' => $userProviderDelegate,
                'security.firewalls' => $securityFirewalls,
                'security.access_rules' => $accessRules,
                'security.role_hierarchy' => $roleHierarchy
            ]
        );

        // register after SecurityServiceProvider
        $app->register(new RememberMeServiceProvider);

        $this->registerAuthenticators($app, $injector, $crateSettings->get('authenticators', new Settings));
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

    protected function registerAuthenticators(
        Container $app,
        Injector $injector,
        SettingsInterface $authenticatorSettings
    ) {
        foreach ($authenticatorSettings as $name => $authenticator) {
            $app[$name] = function () use ($injector, $authenticator) {
                return $injector->make($authenticator);
            };
        }
    }

    public function subscribe(Container $app, EventDispatcherInterface $dispatcher)
    {
        if (isset($app['session'])) {
            $dispatcher->addSubscriber(new UserLocaleListener($app['session']));
        }
    }
}
