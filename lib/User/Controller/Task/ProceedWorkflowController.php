<?php

namespace Hlx\Security\User\Controller\Task;

use Hlx\Security\Service\AccountService;
use Hlx\Security\User\View\Task\ProceedWorkflowSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class ProceedWorkflowController
{
    protected $userService;

    protected $accountService;

    public function __construct(UserProviderInterface $userService, AccountService $accountService)
    {
        $this->userService = $userService;
        $this->accountService = $accountService;
    }

    public function write(Request $request, Application $app)
    {
        $user = $this->userService->loadUserByIdentifier($request->get('identifier'));
        $currentStateName = $request->get('from');
        $eventName = $request->get('via');

        $this->accountService->proceedUserWorkflow($user, $currentStateName, $eventName);

        return [ ProceedWorkflowSuccessView::CLASS ];
    }
}
