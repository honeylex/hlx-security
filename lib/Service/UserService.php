<?php

namespace Foh\SystemAccount\Service;

use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserService implements UserProviderInterface
{
    protected $authService;

    public function __construct(AuthServiceInterface $authService)
    {
        $this->authService = $authService;
    }

    public function loadUserByUsername($username)
    {
        $system_account_user = $this->authService->findByUsername($username);

        if (!$system_account_user) {
            throw new UsernameNotFoundException(sprintf('Username "%s" not found', $username));
        }

        return new User($system_account_user->toArray());
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
}
