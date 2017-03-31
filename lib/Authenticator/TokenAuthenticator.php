<?php

namespace Hlx\Security\Authenticator;

use Hlx\Security\User\ApiUser;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Translation\TranslatorInterface;

class TokenAuthenticator extends AbstractGuardAuthenticator
{
    protected $translator;

    public function __construct(TranslatorInterface $translator)
    {
        $this->translator = $translator;
    }

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

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $user = $userProvider->loadUserByToken($credentials['token'], 'authentication');

        return new ApiUser($user->toArray());
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        if ($user->getUsername() !== $credentials['username']) {
            throw new BadCredentialsException;
        }

        return true;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        sleep(1);
        $message = $exception->getMessage();
        $message = $message ?: $exception->getMessageKey();
        $content = [
            'errors' => [
                'code' => 403,
                'message' => $this->translator->trans($message, [], 'errors')
            ]
        ];

        return new JsonResponse($content, JsonResponse::HTTP_FORBIDDEN);
    }

    // Called when authentication is needed, but it's not sent or is invalid
    public function start(Request $request, AuthenticationException $exception = null)
    {
        if ($exception) {
            $message = $exception->getMessage();
            $message = $message ?: $exception->getMessageKey();
        } else {
            $message = 'Full authentication is required to access this resource.';
        }

        $content = [
            'errors' => [
                'code' => 401,
                'message' => $this->translator->trans($message, [], 'errors')
            ]
        ];

        return new JsonResponse($content, JsonResponse::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
