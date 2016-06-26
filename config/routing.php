<?php

// everything in here will be mounted below the prefix '/foh/system_account'

use Foh\SystemAccount\Controller\IndexController;
use Foh\SystemAccount\Controller\LoginController;
use Foh\SystemAccount\Controller\RegistrationController;

require __DIR__.'/User/routing.php';

$routing->get('/', [ IndexController::CLASS, 'read' ])->bind($this->getPrefix().'.index');
$routing->get('/login', [ LoginController::CLASS, 'read' ])->bind($this->getPrefix().'.login');
$routing->get('/logout', function() {})->bind($this->getPrefix().'.logout');
$routing->match('/login_check', function () {})->bind($this->getPrefix().'.login_check');

$routing->get('/registration', [ RegistrationController::CLASS, 'read' ])->bind($this->getPrefix().'.registration');
$routing->post('/registration', [ RegistrationController::CLASS, 'write' ]);
