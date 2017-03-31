<?php

namespace Hlx\Security\User\Controller\Task;

use Hlx\Security\Service\UserManager;
use Hlx\Security\User\View\Task\ProceedWorkflowSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class ProceedWorkflowController
{
    protected $userProvider;

    protected $userManager;

    public function __construct(UserProviderInterface $userProvider, UserManager $userManager)
    {
        $this->userProvider = $userProvider;
        $this->userManager = $userManager;
    }

    public function write(Request $request, Application $app)
    {
        $user = $this->userProvider->loadUserByIdentifier($request->get('userId'));
        $currentStateName = $request->get('from');
        $eventName = $request->get('via');

        $this->userManager->proceedUserWorkflow($user, $currentStateName, $eventName);

        return [ ProceedWorkflowSuccessView::CLASS ];
    }
}
