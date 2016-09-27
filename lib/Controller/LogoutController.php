<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\AccountService;
use Hlx\Security\View\LogoutSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class LogoutController
{
    protected $tokenStorage;

    protected $accountService;

    public function __construct(TokenStorageInterface $tokenStorage, AccountService $accountService)
    {
        $this->tokenStorage = $tokenStorage;
        $this->accountService = $accountService;
    }

    public function write(Request $request, Application $app)
    {
        $token = $this->tokenStorage->getToken();

        $this->accountService->logoutUser($token->getUser());

        return [ LogoutSuccessView::CLASS ];
    }
}
