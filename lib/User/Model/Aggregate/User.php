<?php

namespace Hlx\Security\User\Model\Aggregate;

use Hlx\Security\User\Model\Aggregate\Base\User as BaseUser;
use Hlx\Security\User\Model\Aggregate\Embed\Authentication;
use Hlx\Security\User\Model\Task\AddToken\TokenAddedEvent;
use Hlx\Security\User\Model\Task\CreateUser\CreateUserCommand;
use Hlx\Security\User\Model\Task\CreateUser\UserCreatedEvent;
use Hlx\Security\User\Model\Task\LogoutUser\LogoutUserCommand;
use Hlx\Security\User\Model\Task\LogoutUser\UserLoggedOutEvent;
use Hlx\Security\User\Model\Task\ModifyToken\TokenModifiedEvent;
use Hlx\Security\User\Model\Task\ModifyUser\UserModifiedEvent;
use Hlx\Security\User\Model\Task\RemoveToken\TokenRemovedEvent;
use Hlx\Security\User\Model\Task\SetUserPassword\SetUserPasswordCommand;
use Hlx\Security\User\Model\Task\SetUserPassword\UserPasswordSetEvent;
use Honeybee\Common\Util\StringToolkit;
use Honeybee\EntityInterface;
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
     * Set password hash and add an authentication token
     */
    public function changePassword(SetUserPasswordCommand $command)
    {
        $this->guardCommandPreConditions($command);
        $authentication_token_uuid = Uuid::uuid4()->toString();
        $verification_token_uuid = $this->getValue('tokens')->getFirst()->getIdentifier();

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
                    'embedded_entity_identifier' => $verification_token_uuid,
                    'embedded_entity_type' => 'verification',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ]),
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $authentication_token_uuid,
                        'token' => StringToolkit::generateRandomToken()
                    ],
                    'position' => 0,
                    'embedded_entity_identifier' => $authentication_token_uuid,
                    'embedded_entity_type' => 'authentication',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }

    /*
     * Adds a child verification token on AR creation
     */
    public function create(CreateAggregateRootCommand $command)
    {
        $initial_data = $this->createInitialData($command);
        $authentication_token_uuid = Uuid::uuid4()->toString();

        $this->applyEvent(new UserCreatedEvent([
            'metadata' => $command->getMetadata(),
            'uuid' => $initial_data['uuid'],
            'seq_number' => 1,
            'aggregate_root_type' => $this->getType()->getPrefix(),
            'aggregate_root_identifier' => $initial_data['identifier'],
            'data' => $initial_data,
            'embedded_entity_events' => new EmbeddedEntityEventList([
                new TokenAddedEvent([
                    'data' => [
                        'identifier' => $authentication_token_uuid,
                        'token' => $command->getVerificationToken()
                    ],
                    'position' => 0,
                    'embedded_entity_identifier' => $authentication_token_uuid,
                    'embedded_entity_type' => 'verification',
                    'parent_attribute_name' => 'tokens',
                    'embedded_entity_events' => []
                ])
            ])
        ]));
    }

    /*
     * Reset authentication token when a user logs out
     */
    public function resetAuthenticationToken(LogoutUserCommand $command)
    {
        foreach ($this->getValue('tokens') as $position => $token) {
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
}
