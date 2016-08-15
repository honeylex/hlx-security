<?php

namespace Hlx\Security\User\Model\Task\LoginUser;

use Hlx\Security\User\Model\Aggregate\UserType;
use Honeybee\Infrastructure\Command\CommandInterface;
use Honeybee\Infrastructure\DataAccess\DataAccessServiceInterface;
use Honeybee\Infrastructure\Event\Bus\EventBusInterface;
use Honeybee\Model\Aggregate\AggregateRootInterface;
use Honeybee\Model\Command\AggregateRootCommandHandler;
use Psr\Log\LoggerInterface;

class LoginUserCommandHandler extends AggregateRootCommandHandler
{
    public function __construct(
        UserType $userType,
        DataAccessServiceInterface $dataAccessService,
        EventBusInterface $eventBus,
        LoggerInterface $logger
    ) {
        parent::__construct($userType, $dataAccessService, $eventBus, $logger);
    }

    protected function doExecute(CommandInterface $command, AggregateRootInterface $user)
    {
        $user->loginUser($command);
    }
}
