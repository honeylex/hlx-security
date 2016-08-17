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
        foreach ($this->getFieldMapping($serviceName) as $attribute => $field) {
            if (isset($rawUserInfo[$field])) {
                $token->setAttribute($attribute, $rawUserInfo[$field]);
            }
        }
    }

    protected function getFieldMapping($serviceName)
    {
        $field_mapping = [];
        if ($service_settings = $this->settings->get($serviceName)) {
            foreach ((array) $service_settings->get('field_mapping') as $mapping) {
                $field_mapping = array_merge($field_mapping, (array) $mapping);
            }
        }
        return $field_mapping;
    }
}
