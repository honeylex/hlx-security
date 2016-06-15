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

        // @todo support override configuration and mount points
        $app->register(
            new SecurityServiceProvider,
            [
                'security.firewalls' => [
                    'login' => [ 'pattern' => '^/foh/system_account/login$' ],
                    'default' => [
                        'pattern' => '^.*$',
                        'stateless' => $settings->get('stateless', false) === true,
                        'anonymous' => false,
                        'remember_me' => [],
                        'form' => [
                            'login_path' => '/foh/system_account/login',
                            'check_path' => '/foh/system_account/login_check',
                            'default_target_path' => '/foh/system_account/user/list'
                        ],
                        'logout' => [
                            'logout_path' => '/foh/system_account/logout',
                            'invalidate_session' => true
                        ],
                        'users' => $injector->make($service)
                    ]
                ]
            ]
        );

        // register after SecurityServiceProvider
        if ($settings->get('stateless', false) !== true) {
            $app->register(new SessionServiceProvider);
            $app->register(new RememberMeServiceProvider);
        }

        parent::provision($app, $injector, $configProvider, $serviceDefinition, $provisionerSettings);

        return $injector;
    }
}