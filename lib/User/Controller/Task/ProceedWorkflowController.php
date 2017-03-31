<?php

namespace Hlx\Security\User\Controller\Task;

use Hlx\Security\Service\AccountService;
use Hlx\Security\User\View\Task\ProceedWorkflowSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class ProceedWorkflowController
{
    protected $userProvider;

    protected $accountService;

    public function __construct(UserProviderInterface $userProvider, AccountService $accountService)
    {
        $this->userProvider = $userProvider;
        $this->accountService = $accountService;
    }

    public function write(Request $request, Application $app)
    {
        $user = $this->userProvider->loadUserByIdentifier($request->get('userId'));
        $currentStateName = $request->get('from');
        $eventName = $request->get('via');

        $this->accountService->proceedUserWorkflow($user, $currentStateName, $eventName);

        return [ ProceedWorkflowSuccessView::CLASS ];
    }
}
