<?php

use Foh\SystemAccount\User\Controller\HistoryController;
use Foh\SystemAccount\User\Controller\ListController;
use Foh\SystemAccount\User\Controller\Task\ModifyController;
use Foh\SystemAccount\User\Controller\Task\ProceedWorkflowController;

$routing->mount('/user', function ($routing) {
    $routing->post('/list', [ ListController::CLASS, 'write' ]);
    $routing->get('/list', [ ListController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.list');

    $routing->post('/{identifier}/tasks/edit', [ ModifyController::CLASS, 'write' ]);
    $routing->get('/{identifier}/tasks/edit', [ ModifyController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.tasks.modify');

    $routing->match('/{identifier}/tasks/proceed', [ ProceedWorkflowController::CLASS, 'write' ])
        ->bind($this->getPrefix().'.user.tasks.proceed');

    $routing->get('/{identifier}/history', [ HistoryController::CLASS, 'read' ])
        ->bind($this->getPrefix().'.user.history');
});
