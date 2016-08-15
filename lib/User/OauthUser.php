<?php

namespace Hlx\Security\User;

use DateTime;

class OauthUser extends User
{
    protected $service;

    public function __construct(array $state, $service)
    {
        parent::__construct($state);
        $this->service = $service;
    }

    public function getService()
    {
        return $this->service;
    }

    public function isCredentialsNonExpired()
    {
        foreach($this->getTokens() as $token) {
            if ($token['@type'] === 'oauth' && $token['service'] === $this->service) {
                return new DateTime('now') < new DateTime($token['expires_at']);
            }
        }

        return false;
    }
}
