<?php

namespace Foh\SystemAccount\Service\Provisioner;

use Auryn\Injector;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\FrameworkBinding\Silex\Service\Provisioner\SilexServiceProvisioner;
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
        $settings = $serviceDefinition->getConfig();
        $serviceKey = $provisionerSettings->get('app_key');

        // allow override of routing prefix from crate settings
        $routing_prefix = $configProvider->getCrateMap()->getItem('foh.system_account')->getRoutingPrefix();
        if ($routing_prefix === '/') {
            $routing_prefix = '';
        }

        // @todo support override security configuration
        $app->register(
            new SecurityServiceProvider,
            [
                'security.firewalls' => [
                    'login' => [ 'pattern' => "^$routing_prefix/login$" ],
                    'registration' => [ 'pattern' => "^$routing_prefix/registration$" ],
                    'password' => [ 'pattern' => "^$routing_prefix/password$" ],
                    'secure' => [
                        'pattern' => '^.*$',
                        'stateless' => $settings->get('stateless', false) === true,
                        'anonymous' => false,
                        'remember_me' => [],
                        'form' => [
                            'login_path' => "$routing_prefix/login",
                            'check_path' => "$routing_prefix/login_check",
                            'default_target_path' => "$routing_prefix/user/list"
                        ],
                        'logout' => [
                            'logout_path' => "$routing_prefix/logout",
                            'invalidate_session' => true
                        ],
                        'users' => function ($app) use ($serviceKey) {
                            return $app[$serviceKey];
                        }
                    ]
                ]
            ]
        );

        // register after SecurityServiceProvider
        if ($settings->get('stateless', false) !== true) {
            $app->register(new SessionServiceProvider);
            $app->register(new RememberMeServiceProvider);
        }

        // looks like we need to make this upfront for the security provider
        $app[$serviceKey] = $injector->make($service);

        parent::provision($app, $injector, $configProvider, $serviceDefinition, $provisionerSettings);

        return $injector;
    }
}
