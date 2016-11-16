<?php

namespace Hlx\Security\User\Model\Task\ConnectService;

use Hlx\Security\User\Model\Aggregate\UserType;
use Honeybee\Infrastructure\Command\CommandInterface;
use Honeybee\Infrastructure\DataAccess\DataAccessServiceInterface;
use Honeybee\Infrastructure\Event\Bus\EventBusInterface;
use Honeybee\Infrastructure\Workflow\WorkflowServiceInterface;
use Honeybee\Model\Aggregate\AggregateRootInterface;
use Honeybee\Model\Command\AggregateRootCommandHandler;
use Psr\Log\LoggerInterface;

class ConnectOauthServiceCommandHandler extends AggregateRootCommandHandler
{
    public function __construct(
        UserType $user_type,
        DataAccessServiceInterface $data_access_service,
        EventBusInterface $event_bus,
        WorkflowServiceInterface $workflow_service,
        LoggerInterface $logger
    ) {
        parent::__construct($user_type, $data_access_service, $event_bus, $workflow_service, $logger);
    }

    protected function doExecute(CommandInterface $command, AggregateRootInterface $user)
    {
        // @todo check service token does not exist already

        $user->connectOauthService($command);
    }
}
