<?php

namespace Hlx\Security\User\Model\Task\ProceedUserWorkflow;

use Honeybee\Model\Task\ProceedWorkflow\ProceedWorkflowCommand;

class ProceedUserWorkflowCommand extends ProceedWorkflowCommand
{
    public function getEventClass()
    {
        return UserWorkflowProceededEvent::CLASS;
    }
}
