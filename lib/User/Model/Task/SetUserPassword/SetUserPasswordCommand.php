<?php

namespace Hlx\Security\User\Model\Task\SetUserPassword;

use Assert\Assertion;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommand;

class SetUserPasswordCommand extends ModifyAggregateRootCommand
{
    protected $password_hash;

    public function __construct(array $state = [])
    {
        $this->values = [];
        parent::__construct($state);
    }

    public function getEventClass()
    {
        return UserPasswordSetEvent::CLASS;
    }

    public function getAffectedAttributeNames()
    {
        return [ 'password_hash' ];
    }

    public function getPasswordHash()
    {
        return $this->password_hash;
    }

    protected function guardRequiredState()
    {
        parent::guardRequiredState();

        Assertion::string($this->password_hash);
        Assertion::notBlank($this->password_hash);
    }
}
