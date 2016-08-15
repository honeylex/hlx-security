<?php

namespace Hlx\Security\Authenticator;

use Hlx\Security\User\ApiUser;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class TokenAuthenticator extends AbstractGuardAuthenticator
{
    public function getCredentials(Request $request)
    {
        // Checks if the credential header is provided
        if (!$credentials = $request->headers->get('X-AUTH-TOKEN')) {
            return;
        }

        // Parse the header or ignore it if the format is incorrect.
        if (false === strpos($credentials, ':')) {
            return;
        }

        list($username, $token) = explode(':', $credentials, 2);

        return [
            'username' => $username,
            'token' => $token,
        ];
    }

    public function getUser($credentials, UserProviderInterface $userService)
    {
        $user = $userService->loadUserByToken($credentials['token'], 'authentication');
        return new ApiUser($user->toArray());
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        return $user->getUsername() === $credentials['username'];
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ];

        return new JsonResponse($data, 403);
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = [
            'message' => 'Authentication Required',
        ];

        return new JsonResponse($data, 401);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
