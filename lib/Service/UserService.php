<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Gigablah\Silex\OAuth\Security\User\Provider\OAuthUserProviderInterface;
use Hlx\Security\User\User;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\TokenNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserService implements UserProviderInterface, PasswordEncoderInterface, OAuthUserProviderInterface
{
    protected $authService;

    protected $registrationService;

    public function __construct(
        AuthServiceInterface $authService,
        RegistrationServiceInterface $registrationService
    ) {
        $this->authService = $authService;
        $this->registrationService = $registrationService;
    }

    public function loadUserByUsername($username)
    {
        $security_user = $this->authService->findByUsername($username);

        if (!$security_user) {
            throw new UsernameNotFoundException;
        }

        return new User($security_user->toArray());
    }

    public function loadUserByToken($token, $type)
    {
        $security_user = $this->authService->findByToken($token, $type);

        if (!$security_user) {
            throw new TokenNotFoundException;
        }

        return new User($security_user->toArray());
    }

    public function loadUserByEmail($email)
    {
        $security_user = $this->authService->findByEmail($email);

        if (!$security_user) {
            throw new AuthenticationException;
        }

        return new User($security_user->toArray());
    }

    public function loadUserByOAuthCredentials(OAuthTokenInterface $token)
    {
        $security_user = $this->authService->findByEmail($token->getEmail());

        if (!$security_user) {
            $this->registrationService->registerOauthUser($token);
            $security_user = $this->authService->findByEmail($token->getEmail());
        } else {
            $this->registrationService->updateOauthUser($security_user, $token);
        }

        if (!$security_user) {
            throw new AuthenticationException;
        }

        $this->registrationService->verifyUser($security_user);

        return new User($security_user->toArray());
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException;
        }

        // @todo called after loadUserByUsername so no need to load user twice?
        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return User::CLASS === $class;
    }

    public function encodePassword($raw, $salt)
    {
        return $this->authService->encodePassword($raw);
    }

    public function isPasswordValid($encoded, $raw, $salt)
    {
        return $this->authService->verifyPassword($raw, $encoded);
    }
}
