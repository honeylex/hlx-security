<?php

namespace Hlx\Security\Authentication;

use Hlx\Security\User\User;
use Honeylex\Config\ConfigProviderInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\AnonymousToken;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/*
 * Ensures session is invalidated when authentication token has changed or expired
 * in a different session or process.
 */
class UserTokenAuthenticator extends AbstractGuardAuthenticator
{
    protected $configProvider;

    protected $tokenStorage;

    protected $urlGenerator;

    public function __construct(
        ConfigProviderInterface $configProvider,
        TokenStorageInterface $tokenStorage,
        UrlGeneratorInterface $urlGenerator
    ) {
        $this->configProvider = $configProvider;
        $this->tokenStorage = $tokenStorage;
        $this->urlGenerator = $urlGenerator;
    }

    public function getCredentials(Request $request)
    {
        $token = $this->tokenStorage->getToken();

        if (!$token || $token instanceof AnonymousToken) {
            return;
        }

        return $token->getUser()->toArray();
    }

    public function getUser($state, UserProviderInterface $userProvider)
    {
        return new User($state);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if (!$user->isAuthenticationTokenNonExpired()) {
            throw new CustomUserMessageAuthenticationException(
                'You have been automatically logged out. Please log in again.'
            );
        }

        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        if ($request->hasSession()) {
            $request->getSession()->set(Security::AUTHENTICATION_ERROR, $exception);
        }

        $this->tokenStorage->setToken(null);

        /*
         * To avoid the subsequent auto-login attempt when using remember me services it would be ideal to
         * cancel the cookie here, but that seems to be a hack. Instead the remember me token is validated
         * in its usual flow but with additional checks which eventually cancel the cookie.
         */

        return new RedirectResponse($this->getLoginUrl());
    }

    public function start(Request $request, AuthenticationException $exception = null)
    {
        // Not intended to act as an entry point guard
    }

    public function supportsRememberMe()
    {
        return false;
    }

    protected function getLoginUrl()
    {
        return $this->urlGenerator->generate('hlx.security.login');
    }
}
