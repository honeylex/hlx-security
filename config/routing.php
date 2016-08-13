<?php

use Hlx\Security\Controller\ForgotPasswordController;
use Hlx\Security\Controller\LoginController;
use Hlx\Security\Controller\RegistrationController;
use Hlx\Security\Controller\SetPasswordController;

require __DIR__.'/User/routing.php';

$routing->get('/login', [ LoginController::CLASS, 'read' ])->bind($this->getPrefix().'.login');
$routing->get('/logout', function() {})->bind($this->getPrefix().'.logout');
$routing->match('/login/check', function () {})->bind($this->getPrefix().'.login.check');

$routing->get('/registration', [ RegistrationController::CLASS, 'read' ])->bind($this->getPrefix().'.registration');
$routing->post('/registration', [ RegistrationController::CLASS, 'write' ]);
$routing->get('/password/set', [ SetPasswordController::CLASS, 'read' ])->bind($this->getPrefix().'.password.set');
$routing->post('/password/set', [ SetPasswordController::CLASS, 'write' ]);
$routing->get('/password/forgot', [ ForgotPasswordController::CLASS, 'read' ])->bind($this->getPrefix().'.password.forgot');
$routing->post('/password/forgot', [ ForgotPasswordController::CLASS, 'write' ]);
$routing->get('/verify', [ RegistrationController::CLASS, 'verify' ])->bind($this->getPrefix().'.verify');
