<?php

namespace Hlx\Security\User\Model\Task\LogoutUser;

use Honeybee\Infrastructure\Command\Command;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommand;

class LogoutUserCommand extends ModifyAggregateRootCommand
{
    public function __construct(array $state = [])
    {
        $this->values = [];
        parent::__construct($state);
    }

    public function getEventClass()
    {
        return UserLoggedOutEvent::CLASS;
    }
}
