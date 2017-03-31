<?php

namespace Hlx\Security\EventListener;

use Honeybee\Common\Error\RuntimeError;
use Hlx\Security\Service\UserManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;

class UserLogoutListener implements LogoutSuccessHandlerInterface
{
    protected $httpUtils;

    protected $tokenStorage;

    protected $userManager;

    protected $targetUrl;

    public function __construct(
        HttpUtils $httpUtils,
        TokenStorageInterface $tokenStorage,
        UserManager $userManager,
        $targetUrl = '/'
    ) {
        $this->httpUtils = $httpUtils;
        $this->tokenStorage = $tokenStorage;
        $this->userManager = $userManager;
        $this->targetUrl = $targetUrl;
    }

    public function onLogoutSuccess(Request $request)
    {
        $token = $this->tokenStorage->getToken();

        if ($token instanceof TokenInterface) {
            $user = $token->getUser();
            try {
                $this->userManager->logoutUser($user);
            } catch (RuntimeError $error) {
            }
        }

        return $this->httpUtils->createRedirectResponse($request, $this->targetUrl);
    }
}
