<?php

use Hlx\Security\Controller\LoginController;
use Hlx\Security\Controller\PasswordController;
use Hlx\Security\Controller\RegistrationController;

require __DIR__.'/User/routing.php';

$routing->get('/login', [ LoginController::CLASS, 'read' ])->bind($this->getPrefix().'.login');
$routing->get('/logout', function() {})->bind($this->getPrefix().'.logout');
$routing->match('/login_check', function () {})->bind($this->getPrefix().'.login_check');

$routing->get('/registration', [ RegistrationController::CLASS, 'read' ])->bind($this->getPrefix().'.registration');
$routing->post('/registration', [ RegistrationController::CLASS, 'write' ]);
$routing->get('/password', [ PasswordController::CLASS, 'read' ])->bind($this->getPrefix().'.password');
$routing->post('/password', [ PasswordController::CLASS, 'write' ]);
