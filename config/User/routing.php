<?php

use Hlx\Security\User\Controller\HistoryController;
use Hlx\Security\User\Controller\ListController;
use Hlx\Security\User\Controller\Task\CreateController;
use Hlx\Security\User\Controller\Task\ModifyController;
use Hlx\Security\User\Controller\Task\ProceedWorkflowController;

$routing->mount('/user', function ($routing) {
    $routing->get('/list', [ ListController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.list');

    $routing->post('/tasks/create', [ CreateController::CLASS, 'write' ]);
    $routing->get('/tasks/create', [ CreateController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.tasks.create');

    $routing->post('/{identifier}/tasks/edit', [ ModifyController::CLASS, 'write' ]);
    $routing->get('/{identifier}/tasks/edit', [ ModifyController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.tasks.modify');

    $routing->match('/{identifier}/tasks/proceed', [ ProceedWorkflowController::CLASS, 'write' ])
        ->bind($this->getPrefix().'.user.tasks.proceed');

    $routing->get('/{identifier}/history', [ HistoryController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.history');
});
