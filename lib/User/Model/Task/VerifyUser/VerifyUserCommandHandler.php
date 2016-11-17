<?php

namespace Hlx\Security\User\Model\Task\VerifyUser;

use Hlx\Security\User\Model\Task\ProceedUserWorkflow\ProceedUserWorkflowCommandHandler;
use Honeybee\Infrastructure\Command\CommandInterface;
use Honeybee\Model\Aggregate\AggregateRootInterface;

class VerifyUserCommandHandler extends ProceedUserWorkflowCommandHandler
{
    protected function doExecute(CommandInterface $command, AggregateRootInterface $user)
    {
        $stateMachine = $this->workflow_service->getStateMachine($user);

        return $user->verifyUser($command, $stateMachine);
    }
}
