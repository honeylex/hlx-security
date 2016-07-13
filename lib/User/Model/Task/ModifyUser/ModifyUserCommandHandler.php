<?php

namespace Hlx\Security\User\Model\Task\ModifyUser;

use Hlx\Security\User\Model\Aggregate\UserType;
use Honeybee\Infrastructure\Event\Bus\EventBusInterface;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommandHandler;
use Honeybee\Infrastructure\DataAccess\DataAccessServiceInterface;
use Psr\Log\LoggerInterface;

class ModifyUserCommandHandler extends ModifyAggregateRootCommandHandler
{
    public function __construct(
        UserType $userType,
        DataAccessServiceInterface $dataAccessService,
        EventBusInterface $eventBus,
        LoggerInterface $logger
    ) {
        parent::__construct($userType, $dataAccessService, $eventBus, $logger);
    }
}
