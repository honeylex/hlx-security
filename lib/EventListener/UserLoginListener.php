<?php

namespace Hlx\Security\EventListener;

use Hlx\Security\Service\AccountService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\HttpUtils;

class UserLoginListener extends DefaultAuthenticationSuccessHandler
{
    protected $accountService;

    public function __construct(
        HttpUtils $httpUtils,
        AccountService $accountService,
        array $options = []
    ) {
        parent::__construct($httpUtils, $options);
        $this->accountService = $accountService;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $user = $token->getUser();

        $this->accountService->loginUser($user);

        return $this->httpUtils->createRedirectResponse($request, $this->determineTargetUrl($request));
    }
}
