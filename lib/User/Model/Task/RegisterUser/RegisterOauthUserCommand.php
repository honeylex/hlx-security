<?php

namespace Hlx\Security\User\Model\Task\RegisterUser;

use Assert\Assertion;

class RegisterOauthUserCommand extends RegisterUserCommand
{
    protected $id;

    protected $service;

    protected $token;

    public function getEventClass()
    {
        return OauthUserRegisteredEvent::CLASS;
    }

    public function getId()
    {
        return $this->id;
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

        Assertion::notEmpty($this->id);
        Assertion::string($this->service);
        Assertion::notBlank($this->service);
        Assertion::string($this->token);
        Assertion::notBlank($this->token);
    }
}
