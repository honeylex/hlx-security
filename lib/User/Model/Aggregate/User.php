<?php

namespace Hlx\Security\User\Model\Aggregate;

use Hlx\Security\User\Model\Aggregate\Base\User as BaseUser;
use Hlx\Security\User\Model\Aggregate\Embed\Authentication;
use Hlx\Security\User\Model\Aggregate\Embed\Oauth;
use Hlx\Security\User\Model\Aggregate\Embed\SetPassword;
use Hlx\Security\User\Model\Aggregate\Embed\Verification;
use Hlx\Security\User\Model\Task\AddToken\TokenAddedEvent;
use Hlx\Security\User\Model\Task\ConnectService\ConnectOauthServiceCommand;
use Hlx\Security\User\Model\Task\ConnectService\OauthServiceConnectedEvent;
use Hlx\Security\User\Model\Task\LoginUser\LoginOauthUserCommand;
use Hlx\Security\User\Model\Task\LoginUser\LoginUserCommand;
use Hlx\Security\User\Model\Task\LoginUser\OauthUserLoggedInEvent;
use Hlx\Security\User\Model\Task\LoginUser\UserLoggedInEvent;
use Hlx\Security\User\Model\Task\LogoutUser\LogoutUserCommand;
use Hlx\Security\User\Model\Task\LogoutUser\UserLoggedOutEvent;
use Hlx\Security\User\Model\Task\ModifyToken\TokenModifiedEvent;
use Hlx\Security\User\Model\Task\RegisterUser\OauthUserRegisteredEvent;
use Hlx\Security\User\Model\Task\RegisterUser\RegisterOauthUserCommand;
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
use Honeybee\Model\Aggregate\WorkflowSubject;
use Honeybee\Model\Event\EmbeddedEntityEventList;
use Honeybee\Model\Task\CreateAggregateRoot\CreateAggregateRootCommand;
use Ramsey\Uuid\Uuid;
use Workflux\StateMachine\StateMachineInterface;

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
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    /*
     * Create a user
     */
    public function create(CreateAggregateRootCommand $command, StateMachineInterface $stateMachine)
    {
        switch (get_class($command)) {
            case RegisterUserCommand::CLASS:
                $this->registerUser($command, $stateMachine);
                break;
            case RegisterOauthUserCommand::CLASS:
                $this->registerOauthUser($command, $stateMachine);
                break;
            default:
                throw new RuntimeError('Unsupported User registration command: '.get_class($command));
        }
    }

    /*
     * Register a standard user
     */
    protected function registerUser(RegisterUserCommand $command, StateMachineInterface $stateMachine)
    {
        $initialData = $this->createInitialData($command, $stateMachine);
        $initialData['role'] = $command->getRole();
        $authenticationTokenUuid = Uuid::uuid4()->toString();
        $verificationTokenUuid = Uuid::uuid4()->toString();

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
                        'identifier' => $authenticationTokenUuid,
                        'token' => StringToolkit::generateRandomToken(),
                        'expires_at' => $command->getExpiresAt()
                    ],
                    'position' => 0,
                    'embedded_entity_identifier' => $authenticationTokenUuid,
                    'embedded_entity_type' => 'authentication',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ]),
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $verificationTokenUuid,
                        'token' => StringToolkit::generateRandomToken()
                    ],
                    'position' => 1,
                    'embedded_entity_identifier' => $verificationTokenUuid,
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
    protected function registerOauthUser(RegisterOauthUserCommand $command, StateMachineInterface $stateMachine)
    {
        $initialData = $this->createInitialData($command, $stateMachine);
        $initialData['role'] = $command->getRole();
        $authenticationTokenUuid = Uuid::uuid4()->toString();
        $serviceTokenUuid = Uuid::uuid4()->toString();

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
                        'identifier' => $authenticationTokenUuid,
                        'token' => StringToolkit::generateRandomToken(),
                        // hardcoding auth token expiry until command delivers a long-lived token
                        'expires_at' => date(self::DATE_ISO8601_WITH_MICROS, time() + (86400 * 30))
                    ],
                    'position' => 0,
                    'embedded_entity_identifier' => $authenticationTokenUuid,
                    'embedded_entity_type' => 'authentication',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ]),
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $serviceTokenUuid,
                        'id' => $command->getId(),
                        'service' => $command->getService(),
                        'token' => $command->getToken(),
                        'expires_at' => $command->getExpiresAt()
                    ],
                    'position' => 1,
                    'embedded_entity_identifier' => $serviceTokenUuid,
                    'embedded_entity_type' => 'oauth',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }

    /*
     * Refresh authentication token when a user logs in
     */
    public function loginUser(LoginUserCommand $command)
    {
        $this->guardCommandPreConditions($command);

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof Authentication) {
                $this->applyEvent(new UserLoggedInEvent([
                    'metadata' => $command->getMetadata(),
                    'uuid' => $this->getUuid(),
                    'seq_number' => $this->getRevision() + 1,
                    'aggregate_root_type' => $this->getType()->getPrefix(),
                    'aggregate_root_identifier' => $this->getIdentifier(),
                    'data' => [],
                    'embedded_entity_events' => new EmbeddedEntityEventList([
                        new TokenModifiedEvent([
                            'data' => [
                                'expires_at' => $command->getExpiresAt()
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
     * Refresh service & authentication token when a user logs in via Oauth
     */
    public function loginOauthUser(LoginOauthUserCommand $command)
    {
        $this->guardCommandPreConditions($command);

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof Oauth && $command->getService() === $token->getService()) {
                $this->applyEvent(new OauthUserLoggedInEvent([
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
                            'embedded_entity_type' => 'oauth',
                            'parent_attribute_name' => 'tokens',
                            'embedded_entity_events' => []
                        ])
                    ])
                ]));
            } elseif ($token instanceof Authentication) {
                $this->applyEvent(new UserLoggedInEvent([
                    'metadata' => $command->getMetadata(),
                    'uuid' => $this->getUuid(),
                    'seq_number' => $this->getRevision() + 1,
                    'aggregate_root_type' => $this->getType()->getPrefix(),
                    'aggregate_root_identifier' => $this->getIdentifier(),
                    'data' => [],
                    'embedded_entity_events' => new EmbeddedEntityEventList([
                        new TokenModifiedEvent([
                            'data' => [
                                'expires_at' => $command->getExpiresAt()
                            ],
                            'position' => $position,
                            'embedded_entity_identifier' => $token->getIdentifier(),
                            'embedded_entity_type' => 'authentication',
                            'parent_attribute_name' => 'tokens',
                            'embedded_entity_events' => []
                        ])
                    ])
                ]));
            }
        }
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
                                'token' => StringToolkit::generateRandomToken(),
                                'expires_at' => date(self::DATE_ISO8601_WITH_MICROS)
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
     * Create Oauth token for service
     */
    public function connectOauthService(ConnectOauthServiceCommand $command)
    {
        $this->guardCommandPreConditions($command);

        $values = $command->getValues();

        // do not overwrite values if already set
        if (!empty($this->getFirstname()) && isset($values['firstname'])) {
            unset($values['firstname']);
        }

        if (!empty($this->getLastname()) && isset($values['lastname'])) {
            unset($values['lastname']);
        }

        $tokenUuid = Uuid::uuid4()->toString();
        $this->applyEvent(new OauthServiceConnectedEvent([
            'metadata' => $command->getMetadata(),
            'uuid' => $this->getUuid(),
            'seq_number' => $this->getRevision() + 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $this->getIdentifier(),
            'data' => $values,
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
    public function verifyUser(VerifyUserCommand $command, StateMachineInterface $stateMachine)
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

        $workflowSubject = new WorkflowSubject($stateMachine->getName(), $this);
        $stateMachine->execute($workflowSubject, $command->getEventName());

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
            }
        }

        $this->applyEvent(new UserVerifiedEvent($eventData));
    }

    public function startSetUserPassword(StartSetUserPasswordCommand $command)
    {
        $this->guardCommandPreConditions($command);

        $eventData = [
            'metadata' => $command->getMetadata(),
            'uuid' => $this->getUuid(),
            'seq_number' => $this->getRevision() + 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $this->getIdentifier(),
            'data' => [],
            'embedded_entity_events' => new EmbeddedEntityEventList
        ];

        foreach ($this->getTokens() as $position => $token) {
            if ($token instanceof SetPassword) {
                if ($token->hasExpired()) {
                    $eventData['embedded_entity_events']->addItem(
                        new TokenModifiedEvent([
                            'data' => [
                                'token' => StringToolkit::generateRandomToken(),
                                'expires_at' => $command->getExpiresAt()
                            ],
                            'position' => $position,
                            'embedded_entity_identifier' => $token->getIdentifier(),
                            'embedded_entity_type' => 'set_password',
                            'parent_attribute_name' => 'tokens',
                            'embedded_entity_events' => []
                        ])
                    );
                    $this->applyEvent(new UserPasswordSetStartedEvent($eventData));
                }
                return;
            }
        }

        /*
         * Add a set password token if one doesn't exist
         */
        $tokenUuid = Uuid::uuid4()->toString();
        $eventData['embedded_entity_events']->addItem(
            new TokenAddedEvent([
                'data' => [
                    'identifier' => $tokenUuid,
                    'token' => StringToolkit::generateRandomToken(),
                    'expires_at' => $command->getExpiresAt()
                ],
                'position' => count($this->getTokens()),
                'embedded_entity_identifier' => $tokenUuid,
                'embedded_entity_type' => 'set_password',
                'parent_attribute_name' => 'tokens',
                'embedded_entity_events' => []
            ])
        );

        $this->applyEvent(new UserPasswordSetStartedEvent($eventData));
    }

    /*
     * Set the password hash and remove token
     */
    public function setUserPassword(SetUserPasswordCommand $command)
    {
        $this->guardCommandPreConditions($command);

        // @todo create or reset auth token when a password is set
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
}
