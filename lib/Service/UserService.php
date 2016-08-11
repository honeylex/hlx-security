<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Gigablah\Silex\OAuth\Security\User\Provider\OAuthUserProviderInterface;
use Hlx\Security\User\User;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\LockedException;
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
            throw new UsernameNotFoundException;
        }

        return new User($security_user->toArray());
    }

    public function loadUserByEmail($email)
    {
        $security_user = $this->authService->findByEmail($email);

        if (!$security_user) {
            throw new UsernameNotFoundException;
        }

        return new User($security_user->toArray());
    }

    public function loadUserByOAuthCredentials(OAuthTokenInterface $token)
    {
        try {
            $user = $this->loadUserByEmail($token->getEmail());
            if ($user->isAccountNonLocked() && $user->isEnabled()) {
                // do not allow deactivated or deleted users to update
                $this->registrationService->updateOauthUser($user, $token);
            } else {
                throw new LockedException;
            }
        } catch (UsernameNotFoundException $error) {
            $this->registrationService->registerOauthUser($token);
            $user = $this->loadUserByEmail($token->getEmail());
        }

        $this->registrationService->verifyUser($user);

        return $user;
    }

    public function loadUserByUsernameOrEmail($username, $email)
    {
        $security_user = $this->authService->findByUsernameOrEmail($username, $email);

        if (!$security_user) {
            throw new UsernameNotFoundException;
        }

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
