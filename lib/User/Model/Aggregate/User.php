<?php

namespace Hlx\Security\User\Model\Aggregate;

use Hlx\Security\User\Model\Aggregate\Base\User as BaseUser;
use Hlx\Security\User\Model\Aggregate\Embed\Authentication;
use Hlx\Security\User\Model\Aggregate\Embed\Oauth;
use Hlx\Security\User\Model\Aggregate\Embed\SetPassword;
use Hlx\Security\User\Model\Aggregate\Embed\Verification;
use Hlx\Security\User\Model\Task\AddToken\TokenAddedEvent;
use Hlx\Security\User\Model\Task\LogoutUser\LogoutUserCommand;
use Hlx\Security\User\Model\Task\LogoutUser\UserLoggedOutEvent;
use Hlx\Security\User\Model\Task\ModifyToken\TokenModifiedEvent;
use Hlx\Security\User\Model\Task\UpdateOauthUser\UpdateOauthUserCommand;
use Hlx\Security\User\Model\Task\UpdateOauthUser\OauthUserUpdatedEvent;
use Hlx\Security\User\Model\Task\ModifyUser\UserModifiedEvent;
use Hlx\Security\User\Model\Task\RegisterOAuthUser\OauthUserRegisteredEvent;
use Hlx\Security\User\Model\Task\RegisterOauthUser\RegisterOauthUserCommand;
use Hlx\Security\User\Model\Task\RegisterUser\RegisterUserCommand;
use Hlx\Security\User\Model\Task\RegisterUser\UserRegisteredEvent;
use Hlx\Security\User\Model\Task\RemoveToken\TokenRemovedEvent;
use Hlx\Security\User\Model\Task\SetUserPassword\SetUserPasswordCommand;
use Hlx\Security\User\Model\Task\SetUserPassword\StartSetUserPasswordCommand;
use Hlx\Security\User\Model\Task\SetUserPassword\UserPasswordSetEvent;
use Hlx\Security\User\Model\Task\SetUserPassword\UserPasswordSetStartedEvent;
use Hlx\Security\User\Model\Task\VerifyUser\UserVerifiedEvent;
use Hlx\Security\User\Model\Task\VerifyUser\VerifyUserCommand;
use Honeybee\Common\Error\RuntimeError;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\EntityInterface;
use Honeybee\Model\Aggregate\WorkflowSubject;
use Honeybee\Model\Event\EmbeddedEntityEventList;
use Honeybee\Model\Task\CreateAggregateRoot\CreateAggregateRootCommand;
use Ramsey\Uuid\Uuid;

/**
 * This class may be used to customize the behaviour of the
 * 'User' entities and has built-in validation and
 * change tracking.
 *
 * Defines a set of attributes that are used to manage a user aggregate-root&#039;s internal state.
 *
 * To get all changes since the last call to 'markClean()' use
 * the 'getChanges()' method. Call 'isClean()' to get a summary.
 *
 * To check if the entity is in a coherent state according
 * to the set attributes use the 'isValid()' method and check the
 * specific validation results via 'getValidationResults()'.
 * Every validation incident above NOTICE level marks this
 * entity as invalid.
 *
 * There is no default entity or type wide validation atm,
 * but this may be implemented via overriding the 'isValid()'
 * method or by registering and implementing change event listeners
 * via the '(add|remove)EntityChangedListener()' methods.
 *
 * For more information and hooks have a look at the base classes.
 */
class User extends BaseUser
{
    /*
     * Set the password hash and remove token
     */
    public function setUserPassword(SetUserPasswordCommand $command)
    {
        $this->guardCommandPreConditions($command);

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof SetPassword) {
                $this->applyEvent(new UserPasswordSetEvent([
                    'metadata' => $command->getMetadata(),
                    'uuid' => $this->getUuid(),
                    'seq_number' => $this->getRevision() + 1,
                    'aggregate_root_type' => $this->getType()->getPrefix(),
                    'aggregate_root_identifier' => $this->getIdentifier(),
                    'data' => [
                        'password_hash' => $command->getPasswordHash()
                    ],
                    'embedded_entity_events' => new EmbeddedEntityEventList([
                        new TokenRemovedEvent([
                            'data' => [],
                            'embedded_entity_identifier' => $token->getIdentifier(),
                            'embedded_entity_type' => 'set_password',
                            'parent_attribute_name' => 'tokens',
                            'embedded_entity_events' => []
                        ])
                    ])
                ]));
                break;
            }
        }
    }

    /*
     * Create a user
     */
    public function create(CreateAggregateRootCommand $command)
    {
        switch (get_class($command)) {
            case RegisterUserCommand::CLASS:
                $this->registerUser($command);
                break;
            case RegisterOauthUserCommand::CLASS:
                $this->registerOauthUser($command);
                break;
            default:
                throw new RuntimeError('Unsupported User registration command: '.get_class($command));
        }
    }

    /*
     * Register a standard user
     */
    protected function registerUser(RegisterUserCommand $command)
    {
        $initialData = $this->createInitialData($command);
        $tokenUuid = Uuid::uuid4()->toString();

        $this->applyEvent(new UserRegisteredEvent([
            'metadata' => $command->getMetadata(),
            'uuid' => $initialData['uuid'],
            'seq_number' => 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $initialData['identifier'],
            'data' => $initialData,
            'embedded_entity_events' => new EmbeddedEntityEventList([
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $tokenUuid,
                        'token' => $command->getToken()
                    ],
                    'position' => 0,
                    'embedded_entity_identifier' => $tokenUuid,
                    'embedded_entity_type' => 'verification',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }

    /*
     * Register a user via Oauth
     */
    protected function registerOauthUser(RegisterOauthUserCommand $command)
    {
        $initialData = $this->createInitialData($command);
        $tokenUuid = Uuid::uuid4()->toString();

        $this->applyEvent(new OauthUserRegisteredEvent([
            'metadata' => $command->getMetadata(),
            'uuid' => $initialData['uuid'],
            'seq_number' => 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $initialData['identifier'],
            'data' => $initialData,
            'embedded_entity_events' => new EmbeddedEntityEventList([
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $tokenUuid,
                        'id' => $command->getId(),
                        'service' => $command->getService(),
                        'token' => $command->getToken(),
                        'expires_at' => $command->getExpiresAt()
                    ],
                    'position' => 0,
                    'embedded_entity_identifier' => $tokenUuid,
                    'embedded_entity_type' => 'oauth',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }

    /*
     * Reset authentication token when a user logs out
     */
    public function logoutUser(LogoutUserCommand $command)
    {
        $this->guardCommandPreConditions($command);

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof Authentication) {
                $this->applyEvent(new UserLoggedOutEvent([
                    'metadata' => $command->getMetadata(),
                    'uuid' => $this->getUuid(),
                    'seq_number' => $this->getRevision() + 1,
                    'aggregate_root_type' => $this->getType()->getPrefix(),
                    'aggregate_root_identifier' => $this->getIdentifier(),
                    'data' => [],
                    'embedded_entity_events' => new EmbeddedEntityEventList([
                        new TokenModifiedEvent([
                            'data' => [
                                'token' => StringToolkit::generateRandomToken()
                            ],
                            'position' => $position,
                            'embedded_entity_identifier' => $token->getIdentifier(),
                            'embedded_entity_type' => 'authentication',
                            'parent_attribute_name' => 'tokens',
                            'embedded_entity_events' => []
                        ])
                    ])
                ]));
                break;
            }
        }
    }

    /*
     * Update or create Oauth token for service
     */
    public function updateOauthUser(UpdateOauthUserCommand $command)
    {
        $this->guardCommandPreConditions($command);

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof Oauth && $token->getValue('service') === $command->getService()) {
                if ($token->getToken() !== $command->getToken()) {
                    // update token only if it has changed
                    $this->applyEvent(new OauthUserUpdatedEvent([
                        'metadata' => $command->getMetadata(),
                        'uuid' => $this->getUuid(),
                        'seq_number' => $this->getRevision() + 1,
                        'aggregate_root_type' => $this->getType()->getPrefix(),
                        'aggregate_root_identifier' => $this->getIdentifier(),
                        'data' => $command->getValues(),
                        'embedded_entity_events' => new EmbeddedEntityEventList([
                            new TokenModifiedEvent([
                                'data' => [
                                    'id' => $command->getId(),
                                    'service' => $command->getService(),
                                    'token' => $command->getToken(),
                                    'expires_at' => $command->getExpiresAt()
                                ],
                                'position' => $position,
                                'embedded_entity_identifier' => $token->getIdentifier(),
                                'embedded_entity_type' => 'oauth',
                                'parent_attribute_name' => 'tokens',
                                'embedded_entity_events' => []
                            ])
                        ])
                    ]));
                }
                return;
            }
        }

        /*
         * Add an Oauth token if one was not found for the given service
         */
        $tokenUuid = Uuid::uuid4()->toString();
        $this->applyEvent(new OauthUserUpdatedEvent([
            'metadata' => $command->getMetadata(),
            'uuid' => $this->getUuid(),
            'seq_number' => $this->getRevision() + 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $this->getIdentifier(),
            'data' => $command->getValues(),
            'embedded_entity_events' => new EmbeddedEntityEventList([
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $tokenUuid,
                        'id' => $command->getId(),
                        'service' => $command->getService(),
                        'token' => $command->getToken(),
                        'expires_at' => $command->getExpiresAt()
                    ],
                    'position' => count($this->getTokens()),
                    'embedded_entity_identifier' => $tokenUuid,
                    'embedded_entity_type' => 'oauth',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }

    /*
     * Verify user account and remove verification token if present
     */
    public function verifyUser(VerifyUserCommand $command)
    {
        $this->guardCommandPreConditions($command);

        if ($command->getCurrentStateName() !== $this->getWorkflowState()) {
            throw new RuntimeError(
                sprintf(
                    'The AR\'s(%s) current state %s does not match the given command state %s.',
                    $this,
                    $this->getWorkflowState(),
                    $command->getCurrentStateName()
                )
            );
        }

        $workflowSubject = new WorkflowSubject($this->state_machine->getName(), $this);
        $this->state_machine->execute($workflowSubject, $command->getEventName());

        $eventData = [
            'metadata' => $command->getMetadata(),
            'uuid' => $this->getUuid(),
            'seq_number' => $this->getRevision() + 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $this->getIdentifier(),
            'data' => [
                'workflow_state' => $workflowSubject->getCurrentStateName(),
                'workflow_parameters' => $workflowSubject->getWorkflowParameters()
            ],
            'embedded_entity_events' => new EmbeddedEntityEventList
        ];

        // @todo make sure embedded events are applied
        $reposition = false;
        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof Verification) {
                $eventData['embedded_entity_events']->addItem(
                    new TokenRemovedEvent([
                        'data' => [],
                        'embedded_entity_identifier' => $token->getIdentifier(),
                        'embedded_entity_type' => 'verification',
                        'parent_attribute_name' => 'tokens',
                        'embedded_entity_events' => []
                    ])
                );
                break;
            }
        }

        $this->applyEvent(new UserVerifiedEvent($eventData));
    }

    public function startSetUserPassword(StartSetUserPasswordCommand $command)
    {
        $this->guardCommandPreConditions($command);

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof SetPassword) {
                if ($token->getExpiresAt()->getTimestamp() <= strtotime('+1 hour')) {
                    // update expiring token only
                    $this->applyEvent(new UserPasswordSetStartedEvent([
                        'metadata' => $command->getMetadata(),
                        'uuid' => $this->getUuid(),
                        'seq_number' => $this->getRevision() + 1,
                        'aggregate_root_type' => $this->getType()->getPrefix(),
                        'aggregate_root_identifier' => $this->getIdentifier(),
                        'data' => [],
                        'embedded_entity_events' => new EmbeddedEntityEventList([
                            new TokenModifiedEvent([
                                'data' => [
                                    'token' => $command->getToken(),
                                    'expires_at' => $command->getExpiresAt()
                                ],
                                'position' => $position,
                                'embedded_entity_identifier' => $token->getIdentifier(),
                                'embedded_entity_type' => 'set_password',
                                'parent_attribute_name' => 'tokens',
                                'embedded_entity_events' => []
                            ])
                        ])
                    ]));
                }
                return;
            }
        }

        /*
         * Add a set password token if one doesn't exist
         */
        $tokenUuid = Uuid::uuid4()->toString();
        $this->applyEvent(new UserPasswordSetStartedEvent([
            'metadata' => $command->getMetadata(),
            'uuid' => $this->getUuid(),
            'seq_number' => $this->getRevision() + 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $this->getIdentifier(),
            'data' => [],
            'embedded_entity_events' => new EmbeddedEntityEventList([
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $tokenUuid,
                        'token' => $command->getToken(),
                        'expires_at' => $command->getExpiresAt()
                    ],
                    'position' => count($this->getTokens()),
                    'embedded_entity_identifier' => $tokenUuid,
                    'embedded_entity_type' => 'set_password',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }
}
