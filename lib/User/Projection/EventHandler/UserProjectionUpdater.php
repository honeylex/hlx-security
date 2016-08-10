<?php

namespace Hlx\Security\User\Projection\EventHandler;

use Hlx\Security\Service\MailService;
use Hlx\Security\User\Model\Task\SetUserPassword\UserPasswordSetEvent;
use Hlx\Security\User\Projection\Standard\Embed\Verification;
use Hlx\Security\User\Projection\Standard\User;
use Honeybee\Infrastructure\Config\ConfigInterface;
use Honeybee\Infrastructure\DataAccess\DataAccessServiceInterface;
use Honeybee\Infrastructure\DataAccess\Query\QueryServiceMap;
use Honeybee\Infrastructure\Event\Bus\EventBusInterface;
use Honeybee\Projection\EventHandler\ProjectionUpdater;
use Honeybee\Projection\ProjectionTypeMap;
use Honeybee\Model\Aggregate\AggregateRootTypeMap;
use Psr\Log\LoggerInterface;

class UserProjectionUpdater extends ProjectionUpdater
{
    protected $mailService;

    public function __construct(
        ConfigInterface $config,
        LoggerInterface $logger,
        DataAccessServiceInterface $dataAccessService,
        QueryServiceMap $queryServiceMap,
        ProjectionTypeMap $projectionTypeMap,
        AggregateRootTypeMap $aggregateRootTypeMap,
        EventBusInterface $eventBus,
        MailService $mailService
    ) {
        parent::__construct(
            $config,
            $logger,
            $dataAccessService,
            $queryServiceMap,
            $projectionTypeMap,
            $aggregateRootTypeMap,
            $eventBus
        );

        $this->mailService = $mailService;
    }

    protected function afterUserPasswordSet(UserPasswordSetEvent $event, User $user)
    {
        foreach ($user->getTokens() as $token) {
            if ($token instanceof Verification) {
                $this->mailService->sendVerificationRequestEmail($token, $user);
                break;
            }
        }
    }
}
