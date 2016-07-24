<?php

namespace Hlx\Security\Service;

use Hlx\Security\User\User;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\TokenNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserService implements UserProviderInterface, PasswordEncoderInterface
{
    protected $authService;

    public function __construct(AuthServiceInterface $authService)
    {
        $this->authService = $authService;
    }

    public function loadUserByUsername($username)
    {
        $security_user = $this->authService->findByUsername($username);

        if (!$security_user) {
            throw new UsernameNotFoundException(sprintf('Username "%s" not found.', $username));
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

    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException(sprintf('User class "%s" is not supported.', get_class($user)));
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
