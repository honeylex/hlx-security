<?php

namespace Hlx\Security\EventListener;

use Honeybee\Common\Error\RuntimeError;
use Hlx\Security\Service\AccountService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Http\Logout\LogoutSuccessHandlerInterface;

class UserLogoutListener implements LogoutSuccessHandlerInterface
{
    protected $httpUtils;

    protected $tokenStorage;

    protected $accountService;

    protected $targetUrl;

    public function __construct(
        HttpUtils $httpUtils,
        TokenStorageInterface $tokenStorage,
        AccountService $accountService,
        $targetUrl = '/'
    ) {
        $this->httpUtils = $httpUtils;
        $this->tokenStorage = $tokenStorage;
        $this->accountService = $accountService;
        $this->targetUrl = $targetUrl;
    }

    public function onLogoutSuccess(Request $request)
    {
        $token = $this->tokenStorage->getToken();

        if ($token instanceof TokenInterface) {
            $user = $token->getUser();
            try {
                $this->accountService->logoutUser($user);
            } catch (RuntimeError $error) {
            }
        }

        return $this->httpUtils->createRedirectResponse($request, $this->targetUrl);
    }
}
