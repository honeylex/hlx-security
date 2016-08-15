<?php

namespace Hlx\Security\User\Model\Task\LoginUser;

use Assert\Assertion;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommand;

class LoginOauthUserCommand extends ModifyAggregateRootCommand
{
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    protected $service;

    protected $token;

    protected $expires_at;

    public function __construct(array $state = [])
    {
        $this->values = [];
        parent::__construct($state);
    }

    public function getEventClass()
    {
        return OauthUserLoggedInEvent::CLASS;
    }

    public function getService()
    {
        return $this->service;
    }

    public function getExpiresAt()
    {
        return $this->expires_at;
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
        Assertion::date($this->expires_at, self::DATE_ISO8601_WITH_MICROS);
        Assertion::string($this->token);
        Assertion::notBlank($this->token);
    }
}
