<?php

namespace Hlx\Security\User\Controller\Task;

use Hlx\Security\Service\AccountService;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\RuntimeException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class ProceedWorkflowController
{
    protected $userService;

    protected $accountService;

    protected $urlGenerator;

    public function __construct(
        UserProviderInterface $userService,
        AccountService $accountService,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->userService = $userService;
        $this->accountService = $accountService;
        $this->urlGenerator = $urlGenerator;
    }

    public function write(Request $request, Application $app)
    {
        $user = $this->userService->loadUserByIdentifier($request->get('identifier'));
        $currentStateName = $request->get('from');
        $eventName = $request->get('via');

        try {
            $this->accountService->proceedUserWorkflow($user, $currentStateName, $eventName);
        } catch (RuntimeException $error) {
            return $this->templateRenderer->render(
                '@hlx-security/user/list.html.twig',
                [ 'errors' => (array) $error->getMessageKey() ]
            );
        }

        return $app->redirect($this->urlGenerator->generate('hlx.security.user.list'));
    }
}
