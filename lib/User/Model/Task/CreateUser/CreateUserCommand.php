<?php

namespace Hlx\Security\User\Model\Task\CreateUser;

use Assert\Assertion;
use Honeybee\Model\Task\CreateAggregateRoot\CreateAggregateRootCommand;

class CreateUserCommand extends CreateAggregateRootCommand
{
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    protected $verification_expires_at;

    protected $verification_token;

    public function getEventClass()
    {
        return UserCreatedEvent::CLASS;
    }

    public function getVerificationExpiresAt()
    {
        return $this->verification_expires_at;
    }

    public function getVerificationToken()
    {
        return $this->verification_token;
    }

    protected function guardRequiredState()
    {
        parent::guardRequiredState();

        if (!is_null($this->verification_expires_at)) {
            Assertion::date($this->verification_expires_at, self::DATE_ISO8601_WITH_MICROS);
        }
        Assertion::regex($this->verification_token, '#\w{16,64}#i');
    }
}
