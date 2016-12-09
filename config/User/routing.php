<?php

use Hlx\Security\User\Controller\CollectionController;
use Hlx\Security\User\Controller\HistoryController;
use Hlx\Security\User\Controller\ResourceController;
use Hlx\Security\User\Controller\Task\CreateController;
use Hlx\Security\User\Controller\Task\ModifyController;
use Hlx\Security\User\Controller\Task\ProceedWorkflowController;

$routing->mount('/users', function ($routing) {
    $routing->get('/', [ CollectionController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.users');

    $routing->post('/tasks/create', [ CreateController::CLASS, 'write' ]);
    $routing->get('/tasks/create', [ CreateController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.users.tasks.create');

    $routing->get('/{userId}', [ ResourceController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.users.user');

    $routing->post('/{userId}/tasks/edit', [ ModifyController::CLASS, 'write' ]);
    $routing->get('/{userId}/tasks/edit', [ ModifyController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.users.tasks.modify');

    $routing->match('/{userId}/tasks/proceed', [ ProceedWorkflowController::CLASS, 'write' ])
        ->bind($this->getPrefix().'.users.tasks.proceed');

    $routing->get('/{userId}/history', [ HistoryController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.users.history');
});
