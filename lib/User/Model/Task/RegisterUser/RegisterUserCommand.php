<?php

namespace Hlx\Security\User\Model\Task\RegisterUser;

use Assert\Assertion;
use Honeybee\Model\Task\CreateAggregateRoot\CreateAggregateRootCommand;

class RegisterUserCommand extends CreateAggregateRootCommand
{
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    protected $role;

    protected $expires_at;

    public function getEventClass()
    {
        return UserRegisteredEvent::CLASS;
    }

    public function getRole()
    {
        return $this->role;
    }

    public function getExpiresAt()
    {
        return $this->expires_at;
    }

    protected function guardRequiredState()
    {
        parent::guardRequiredState();

        Assertion::string($this->role);
        Assertion::notBlank($this->role);
        Assertion::date($this->expires_at, self::DATE_ISO8601_WITH_MICROS);
    }
}
