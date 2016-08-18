<?php

namespace Hlx\Security\EventListener;

use Gigablah\Silex\OAuth\EventListener\UserInfoListener;
use Gigablah\Silex\OAuth\OAuthServiceRegistry;
use Honeybee\Infrastructure\Config\Settings;
use Honeybee\Infrastructure\Config\SettingsInterface;

class OauthInfoListener extends UserInfoListener
{
    protected $settings;

    public function __construct(OAuthServiceRegistry $registry, array $config = [], SettingsInterface $settings = null)
    {
        parent::__construct($registry, $config);
        $this->settings = $settings ?: new Settings;
    }

    protected function defaultUserCallback($token, $rawUserInfo, $service)
    {
        parent::defaultUserCallback($token, $rawUserInfo, $service);

        $serviceName = strtolower($token->getService());

        // add additional attributes to a token from service field mapping configuration
        $serviceSettings = $this->settings->get($serviceName, new Settings);
        $fieldMapping = (array) $serviceSettings->get('field_mapping', []);

        foreach ($fieldMapping as $attribute => $field) {
            if (isset($rawUserInfo[$field])) {
                $token->setAttribute($attribute, $rawUserInfo[$field]);
            }
        }
    }
}
