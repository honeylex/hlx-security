<?php

namespace Hlx\Security\User\Model\Task\LoginUser;

use Honeybee\Infrastructure\Command\CommandInterface;
use Honeybee\Model\Aggregate\AggregateRootInterface;

class LoginOauthUserCommandHandler extends LoginUserCommandHandler
{
    protected function doExecute(CommandInterface $command, AggregateRootInterface $user)
    {
        $user->loginOauthUser($command);
    }
}
