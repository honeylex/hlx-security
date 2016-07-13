<?php

namespace Hlx\Security\User\Model\Task\CreateUser;

use Honeybee\Model\Task\CreateAggregateRoot\CreateAggregateRootCommand;

class CreateUserCommand extends CreateAggregateRootCommand
{
    public function getEventClass()
    {
        return UserCreatedEvent::CLASS;
    }
}
