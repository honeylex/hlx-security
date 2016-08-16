<?php

namespace Hlx\Security\User\Model\Task\LoginUser;

use Assert\Assertion;

class LoginOauthUserCommand extends LoginUserCommand
{
    protected $service;

    protected $token;

    public function getEventClass()
    {
        return OauthUserLoggedInEvent::CLASS;
    }

    public function getService()
    {
        return $this->service;
    }

    public function getToken()
    {
        return $this->token;
    }

    protected function guardRequiredState()
    {
        parent::guardRequiredState();

        Assertion::string($this->service);
        Assertion::notBlank($this->service);
        Assertion::string($this->token);
        Assertion::notBlank($this->token);
    }
}
