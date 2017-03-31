<?php

namespace Hlx\Security\Controller;

use Hlx\Security\Service\UserManager;
use Hlx\Security\View\LogoutSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

class LogoutController
{
    protected $tokenStorage;

    protected $userManager;

    public function __construct(TokenStorageInterface $tokenStorage, UserManager $userManager)
    {
        $this->tokenStorage = $tokenStorage;
        $this->userManager = $userManager;
    }

    public function write(Request $request, Application $app)
    {
        $token = $this->tokenStorage->getToken();

        $this->userManager->logoutUser($token->getUser());

        return [ LogoutSuccessView::CLASS ];
    }
}
