<?php

namespace Hlx\Security\Authenticator;

use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\AuthenticationTrustResolverInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class OauthAuthenticator extends AbstractGuardAuthenticator
{
    protected $tokenStorage;

    protected $trustResolver;

    public function __construct(
        TokenStorageInterface $tokenStorage,
        AuthenticationTrustResolverInterface $trustResolver
    ) {
        $this->tokenStorage = $tokenStorage;
        $this->trustResolver = $trustResolver;
    }

    public function getCredentials(Request $request)
    {
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $token = $this->tokenStorage->getToken();
        if ($token && !$this->trustResolver->isAnonymous($token)) {
            return $token->getUser();
        }
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        if ($targetPath = $request->getSession()->get('_security.target_path')) {
            return new RedirectResponse($targetPath);
        }
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
    }

    public function supportsRememberMe()
    {
        return true;
    }
}
