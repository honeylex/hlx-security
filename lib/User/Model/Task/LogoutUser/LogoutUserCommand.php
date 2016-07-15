<?php

namespace Hlx\Security\User\Model\Task\LogoutUser;

use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommand;

class LogoutUserCommand extends ModifyAggregateRootCommand
{
    public function getEventClass()
    {
        return UserLoggedOutEvent::CLASS;
    }
}
