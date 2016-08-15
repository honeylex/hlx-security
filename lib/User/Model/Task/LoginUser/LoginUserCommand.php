<?php

namespace Hlx\Security\User\Model\Task\LoginUser;

use Assert\Assertion;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommand;

class LoginUserCommand extends ModifyAggregateRootCommand
{
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    protected $expires_at;

    public function __construct(array $state = [])
    {
        $this->values = [];
        parent::__construct($state);
    }

    public function getEventClass()
    {
        return UserLoggedInEvent::CLASS;
    }

    public function getExpiresAt()
    {
        return $this->expires_at;
    }

    protected function guardRequiredState()
    {
        parent::guardRequiredState();

        Assertion::date($this->expires_at, self::DATE_ISO8601_WITH_MICROS);
    }
}
