<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Gigablah\Silex\OAuth\Security\User\Provider\OAuthUserProviderInterface;
use Hlx\Security\User\OauthUser;
use Hlx\Security\User\User;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserService implements UserProviderInterface, PasswordEncoderInterface, OAuthUserProviderInterface
{
    protected $authService;

    protected $accountService;

    public function __construct(
        AuthServiceInterface $authService,
        AccountService $accountService
    ) {
        $this->authService = $authService;
        $this->accountService = $accountService;
    }

    public function loadUserByIdentifier($identifier)
    {
        $security_user = $this->authService->findByIdentifier($identifier);

        if (!$security_user) {
            throw new UsernameNotFoundException;
        }

        return new User($security_user->toArray());
    }

    public function loadUserByUsername($username)
    {
        $security_user = $this->authService->findByUsernameOrEmail($username);

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
        $email = $token->getEmail();

        try {
            $user = $this->loadUserByEmail($email);
            $this->accountService->handleOauthUser($user, $token);
        } catch (UsernameNotFoundException $error) {
            $this->accountService->registerOauthUser($token);
        }

        // load again to get updated token and proceed workflow
        $user = $this->loadUserByEmail($email);
        $this->accountService->verifyUser($user);

        // @note may need to refresh workflow state although refreshUser is
        // typically called by framework on next page load anyway

        return new OauthUser($user->toArray(), $token->getService());
    }

    public function userExists($username, $email, array $ignoreIds = [])
    {
        $result = $this->authService->findAllByUsernameOrEmail($username, $email, $ignoreIds);
        return $result->getTotalCount() > 0;
    }

    public function refreshUser(UserInterface $user)
    {
        if (!$this->supportsClass(get_class($user))) {
            throw new UnsupportedUserException;
        }

        $refreshedUser = $this->loadUserByIdentifier($user->getIdentifier());

        return $user->createCopyWith($refreshedUser->toArray());
    }

    public function supportsClass($class)
    {
        return User::CLASS === $class || is_subclass_of($class, User::CLASS);
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
