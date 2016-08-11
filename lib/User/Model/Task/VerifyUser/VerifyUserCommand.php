<?php

namespace Hlx\Security\User\Model\Task\VerifyUser;

use Hlx\Security\User\Model\Task\ProceedUserWorkflow\ProceedUserWorkflowCommand;

class VerifyUserCommand extends ProceedUserWorkflowCommand
{
    public function __construct(array $state = [])
    {
        $this->current_state_name = 'unverified';
        $this->event_name = 'promote';

        parent::__construct($state);
    }

    public function getEventClass()
    {
        return UserVerifiedEvent::CLASS;
    }
}
