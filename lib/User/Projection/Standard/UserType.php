<?php

namespace Hlx\Security\User\Projection\Standard;

use Hlx\Security\User\Projection\Standard\Base\UserType as BaseUserType;

/**
 * Defines the (normalized) strucuture of a default user projection.
 *
 * This class reflects the declared structure of the 'User'
 * entity. It contains the metadata necessary to initiate and manage the
 * lifecycle of 'UserEntity' instances. Most importantly
 * it holds a collection of attributes (and default attributes) that each of the
 * entities of this type supports.
 *
 * For more information and hooks have a look at the base classes.
 */
class UserType extends BaseUserType
{
}
