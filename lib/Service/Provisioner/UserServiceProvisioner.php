<?php

namespace Hlx\Security\Service\Provisioner;

use Auryn\Injector;
use Honeybee\FrameworkBinding\Silex\Config\ConfigProviderInterface;
use Honeybee\FrameworkBinding\Silex\Service\Provisioner\SilexServiceProvisioner;
use Honeybee\Infrastructure\Config\SettingsInterface;
use Honeybee\ServiceDefinitionInterface;
use Pimple\Container;
use Silex\Provider\RememberMeServiceProvider;
use Silex\Provider\SecurityServiceProvider;
use Silex\Provider\SessionServiceProvider;
use Symfony\Component\Security\Core\Encoder\EncoderFactory;

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

        // looks like we need to make this upfront for the security provider
        $app[$serviceKey] = $injector->make($service);

        // logout handler registration
        $app['security.authentication.logout_handler.secure'] = function () use ($injector, $provisionerSettings) {
            return $injector->make($provisionerSettings->get('logout_handler'));
        };

        // allow override of routing prefix from crate settings
        $routing_prefix = $crate->getRoutingPrefix();
        if ($routing_prefix === '/') {
            $routing_prefix = '';
        }

        // @todo support override security configuration
        $app->register(
            new SecurityServiceProvider,
            [
                'security.encoder_factory' => function ($app) use ($serviceKey) {
                    return new EncoderFactory([
                        'hlx.security.encoder' => $app[$serviceKey]
                    ]);
                },
                'security.firewalls' => [
                    'login' => [ 'pattern' => "^$routing_prefix/login$" ],
                    'registration' => [ 'pattern' => "^$routing_prefix/registration$" ],
                    'password' => [ 'pattern' => "^$routing_prefix/password$" ],
                    'secure' => [
                        'pattern' => '^.*$',
                        'stateless' => $provisionerSettings->get('stateless', false) === true,
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
        if ($provisionerSettings->get('stateless', false) !== true) {
            $app->register(new SessionServiceProvider);
            $app->register(new RememberMeServiceProvider);
        }

        parent::provision($app, $injector, $configProvider, $serviceDefinition, $provisionerSettings);

        return $injector;
    }
}
