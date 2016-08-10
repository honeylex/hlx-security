<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\RegisterOauthUser\RegisterOauthUserCommand;
use Hlx\Security\User\Model\Task\RegisterUser\RegisterUserCommand;
use Hlx\Security\User\Model\Task\VerifyUser\VerifyUserCommand;
use Hlx\Security\User\Model\Task\UpdateOauthUser\UpdateOauthUserCommand;
use Hlx\Security\User\User;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Honeybee\Model\Command\AggregateRootCommandBuilder;
use Psr\Log\LoggerInterface;
use Shrink0r\Monatic\Success;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;

class RegistrationService implements RegistrationServiceInterface
{
    protected $userType;

    protected $commandBus;

    protected $logger;

    public function __construct(UserType $userType, CommandBusInterface $commandBus, LoggerInterface $logger)
    {
        $this->userType = $userType;
        $this->commandBus = $commandBus;
        $this->logger = $logger;
    }

    public function registerUser(array $values, $token = null)
    {
        if (empty($token)) {
            $token = StringToolkit::generateRandomToken();
        }

        $result = (new AggregateRootCommandBuilder($this->userType, RegisterUserCommand::CLASS))
            ->withValues($values)
            ->withVerificationToken($token)
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

    public function updateOauthUser(User $user, OAuthTokenInterface $token)
    {
        $serviceName = $token->getService();

        $result = (new AggregateRootCommandBuilder($this->userType, UpdateOauthUserCommand::CLASS))
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
                UpdateOauthUserCommand::DATE_ISO8601_WITH_MICROS,
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
        if ($user->getWorkflowState() === 'verified') {
            return;
        }

        if ($user->getWorkflowState() !== 'unverified') {
            throw new CustomUserMessageAuthenticationException(
                sprintf('Cannot verify user "%s".', $user->getUsername())
            );
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
}
