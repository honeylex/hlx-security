<?php

namespace Hlx\Security\Service;

use Gigablah\Silex\OAuth\Security\Authentication\Token\OAuthTokenInterface;
use Hlx\Security\User\Model\Aggregate\UserType;
use Hlx\Security\User\Model\Task\ProceedUserWorkflow\ProceedUserWorkflowCommand;
use Hlx\Security\User\Model\Task\RegisterOauthUser\RegisterOauthUserCommand;
use Hlx\Security\User\Model\Task\UpdateOauthUser\UpdateOauthUserCommand;
use Hlx\Security\User\Projection\Standard\User;
use Honeybee\Infrastructure\Command\Bus\CommandBusInterface;
use Honeybee\Model\Command\AggregateRootCommandBuilder;
use Shrink0r\Monatic\Success;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

class StandardRegistrationService implements RegistrationServiceInterface
{
    protected $userType;

    protected $commandBus;

    public function __construct(UserType $userType, CommandBusInterface $commandBus)
    {
        $this->userType = $userType;
        $this->commandBus = $commandBus;
    }

    public function registerOauthUser(OAuthTokenInterface $token)
    {
        $serviceName = $token->getService();
        $result = (new AggregateRootCommandBuilder($this->userType, RegisterOauthUserCommand::CLASS))
            ->withValues([
                'username' => $token->getUsername(),
                'email' => $token->getEmail(),
                'firstname' => $token->getAttribute('firstname'),
                'lastname' => $token->getAttribute('lastname'),
                'role' => 'user'
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
            throw new AuthenticationException(sprintf('Error registering %s user.', $serviceName));
        }

        $this->commandBus->post($result->get());
    }

    public function updateOauthUser(User $user, OAuthTokenInterface $token)
    {
        $serviceName = $token->getService();
        $result = (new AggregateRootCommandBuilder($this->userType, UpdateOauthUserCommand::CLASS))
            ->fromEntity($user)
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
            throw new AuthenticationException(sprintf('Error updating %s user.', $serviceName));
        }

        $this->commandBus->post($result->get());
    }

    public function verifyUser(User $user)
    {
        $currentStateName = $user->getWorkflowState();
        if ($currentStateName === 'unverified') {
            $result = (new AggregateRootCommandBuilder($this->userType, ProceedUserWorkflowCommand::CLASS))
                ->fromEntity($user)
                ->withCurrentStateName($currentStateName)
                ->withEventName('promote')
                ->build();

            if (!$result instanceof Success) {
                throw new AuthenticationException('Error verifying user.');
            }

            $this->commandBus->post($result->get());
        }
    }
}
