<?php

namespace Hlx\Security\EventListener;

use Hlx\Security\Service\UserManager;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\Authentication\DefaultAuthenticationSuccessHandler;
use Symfony\Component\Security\Http\HttpUtils;

class UserLoginListener extends DefaultAuthenticationSuccessHandler
{
    protected $userManager;

    public function __construct(
        HttpUtils $httpUtils,
        UserManager $userManager,
        array $options = []
    ) {
        parent::__construct($httpUtils, $options);
        $this->userManager = $userManager;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token)
    {
        $user = $token->getUser();

        $this->userManager->loginUser($user);

        return $this->httpUtils->createRedirectResponse($request, $this->determineTargetUrl($request));
    }
}
