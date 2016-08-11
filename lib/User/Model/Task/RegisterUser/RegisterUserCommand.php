<?php

namespace Hlx\Security\User\Model\Task\RegisterUser;

use Assert\Assertion;
use Honeybee\Model\Task\CreateAggregateRoot\CreateAggregateRootCommand;

class RegisterUserCommand extends CreateAggregateRootCommand
{
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    protected $expires_at;

    protected $token;

    public function getEventClass()
    {
        return UserRegisteredEvent::CLASS;
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

        Assertion::nullOrDate($this->expires_at, self::DATE_ISO8601_WITH_MICROS);
        Assertion::regex($this->token, '#\w{16,64}#i');
    }
}
