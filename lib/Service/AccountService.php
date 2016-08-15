<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\ConnectOauthUser\ConnectOauthUserCommand;
use Hlx\Security\User\Model\Task\LoginUser\LoginOauthUserCommand;
use Hlx\Security\User\Model\Task\LoginUser\LoginUserCommand;
use Hlx\Security\User\Model\Task\LogoutUser\LogoutUserCommand;
use Hlx\Security\User\Model\Task\ModifyUser\ModifyUserCommand;
use Hlx\Security\User\Model\Task\RegisterOauthUser\RegisterOauthUserCommand;
use Hlx\Security\User\Model\Task\RegisterUser\RegisterUserCommand;
use Hlx\Security\User\Model\Task\SetUserPassword\SetUserPasswordCommand;
use Hlx\Security\User\Model\Task\SetUserPassword\StartSetUserPasswordCommand;
use Hlx\Security\User\Model\Task\VerifyUser\VerifyUserCommand;
use Hlx\Security\User\User;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Honeybee\Infrastructure\Security\Auth\AuthServiceInterface;
use Honeybee\Model\Command\AggregateRootCommandBuilder;
use Psr\Log\LoggerInterface;
use Shrink0r\Monatic\Success;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\DisabledException;
use Symfony\Component\Security\Core\Exception\LockedException;
use Symfony\Component\Security\Core\Exception\LogoutException;
use Symfony\Component\Security\Core\Exception\RuntimeException;

class AccountService
{
    protected $userType;

    protected $commandBus;

    protected $authService;

    protected $logger;

    public function __construct(
        UserType $userType,
        CommandBusInterface $commandBus,
        AuthServiceInterface $authService,
        LoggerInterface $logger
    ) {
        $this->userType = $userType;
        $this->commandBus = $commandBus;
        $this->authService = $authService;
        $this->logger = $logger;
    }

    public function registerUser(array $values)
    {
        if (isset($values['password'])) {
            $values['password_hash'] = $this->authService->encodePassword($values['password']);
            unset($values['password']);
        }

        $result = (new AggregateRootCommandBuilder($this->userType, RegisterUserCommand::CLASS))
            ->withValues($values)
            ->withExpiresAt(date(
                RegisterUserCommand::DATE_ISO8601_WITH_MICROS,
                time() + (86400 * 30) // 30 days
            ))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException('Error registering user.');
        }

        $this->commandBus->post($result->get());
    }

    public function registerOauthUser(OAuthTokenInterface $token, $role = 'user')
    {
        $serviceName = $token->getService();

        $result = (new AggregateRootCommandBuilder($this->userType, RegisterOauthUserCommand::CLASS))
            ->withValues([
                'username' => $token->getUsername(),
                'email' => $token->getEmail(),
                'firstname' => $token->getAttribute('firstname'),
                'lastname' => $token->getAttribute('lastname'),
                'role' => $role
            ])
            ->withId($token->getUid())
            ->withService($serviceName)
            ->withToken($token->getCredentials())
            ->withExpiresAt(date(
                RegisterOauthUserCommand::DATE_ISO8601_WITH_MICROS,
                $token->getAccessToken()->getEndOfLife()
            ))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error registering user via %s.', $serviceName)
            );
        }

        $this->commandBus->post($result->get());
    }

    public function updateUser(User $user, array $values)
    {
        $result = (new AggregateRootCommandBuilder($this->userType, ModifyUserCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withValues($values)
            ->build();

        if (!$result instanceof Success) {
            throw new RuntimeException(
                sprintf('Error updating user "%s".', $user->getUsername())
            );
        }

        $this->commandBus->post($result->get());
    }

    public function handleOauthUser(User $user, OAuthTokenInterface $token)
    {
        $serviceName = $token->getService();

        foreach($user->getTokens() as $userToken) {
            if ($userToken['@type'] === 'oauth' && $userToken['service'] == $serviceName) {
                // Log in instead of connect
                $this->loginOauthUser($user, $token);
                return;
            }
        }

        $this->connectOauthUser($user, $token);
    }

    public function connectOauthUser(User $user, OAuthTokenInterface $token)
    {
        $this->guardUserStatus($user);

        $serviceName = $token->getService();

        $result = (new AggregateRootCommandBuilder($this->userType, ConnectOauthUserCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withValues([
                'firstname' => $token->getAttribute('firstname'),
                'lastname' => $token->getAttribute('lastname')
            ])
            ->withId($token->getUid())
            ->withService($serviceName)
            ->withToken($token->getCredentials())
            ->withExpiresAt(date(
                ConnectOauthUserCommand::DATE_ISO8601_WITH_MICROS,
                $token->getAccessToken()->getEndOfLife()
            ))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error updating user "%s" via %s.', $user->getUsername(), $serviceName)
            );
        }

        $this->commandBus->post($result->get());
    }

    public function verifyUser(User $user)
    {
        $this->guardUserStatus($user);

        if ($user->isVerified()) {
            return;
        }

        $result = (new AggregateRootCommandBuilder($this->userType, VerifyUserCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error verifying user "%s".', $user->getUsername())
            );
        }

        $this->commandBus->post($result->get());
    }

    public function startSetUserPassword(User $user)
    {
        $this->guardUserStatus($user);

        $result = (new AggregateRootCommandBuilder($this->userType, StartSetUserPasswordCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withExpiresAt(date(
                StartSetUserPasswordCommand::DATE_ISO8601_WITH_MICROS,
                time() + 600 // 10 minutes between resets
            ))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error starting to set user "%s" password.', $user->getUsername())
            );
        }

        $this->commandBus->post($result->get());
    }

    public function setUserPassword(User $user, $password)
    {
        $this->guardUserStatus($user);

        $result = (new AggregateRootCommandBuilder($this->userType, SetUserPasswordCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withPasswordHash($this->authService->encodePassword($password))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error setting password for user "%s".', $user->getUsername())
            );
        }

        $this->commandBus->post($result->get());
    }

    public function loginUser(User $user)
    {
        $result = (new AggregateRootCommandBuilder($this->userType, LoginUserCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withExpiresAt(date(
                LoginUserCommand::DATE_ISO8601_WITH_MICROS,
                time() + (86400 * 30) // 30 days
            ))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error logging in user "%s".', $user->getUsername())
            );
        }

        $this->commandBus->post($result->get());
    }

    public function loginOauthUser(User $user, OAuthTokenInterface $token)
    {
        $serviceName = $token->getService();

        $result = (new AggregateRootCommandBuilder($this->userType, LoginOauthUserCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->withId($token->getUid())
            ->withService($serviceName)
            ->withToken($token->getCredentials())
            ->withExpiresAt(date(
                LoginOauthUserCommand::DATE_ISO8601_WITH_MICROS,
                $token->getAccessToken()->getEndOfLife()
            ))
            ->build();

        if (!$result instanceof Success) {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Error logging in user "%s" via %s.', $user->getUsername(), $serviceName)
            );
        }

        $this->commandBus->post($result->get());
    }

    public function logoutUser(User $user)
    {
        $result = (new AggregateRootCommandBuilder($this->userType, LogoutUserCommand::CLASS))
            ->withAggregateRootIdentifier($user->getIdentifier())
            ->withKnownRevision($user->getRevision())
            ->build();

        if (!$result instanceof Success) {
            throw new LogoutException;
        }

        $this->commandBus->post($result->get());
    }

    protected function guardUserStatus(User $user)
    {
        if (!$user->isAccountNonLocked()) {
            throw new LockedException;
        }

        if (!$user->isEnabled()) {
            throw new DisabledException;
        }
    }
}
