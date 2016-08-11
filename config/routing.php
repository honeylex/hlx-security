<?php

use Hlx\Security\Controller\ForgotPasswordController;
use Hlx\Security\Controller\LoginController;
use Hlx\Security\Controller\RegistrationController;
use Hlx\Security\Controller\SetPasswordController;

require __DIR__.'/User/routing.php';

$routing->get('/login', [ LoginController::CLASS, 'read' ])->bind($this->getPrefix().'.login');
$routing->get('/logout', function() {})->bind($this->getPrefix().'.logout');
$routing->match('/login_check', function () {})->bind($this->getPrefix().'.login_check');

$routing->get('/registration', [ RegistrationController::CLASS, 'read' ])->bind($this->getPrefix().'.registration');
$routing->post('/registration', [ RegistrationController::CLASS, 'write' ]);
$routing->get('/set_password', [ SetPasswordController::CLASS, 'read' ])->bind($this->getPrefix().'.set_password');
$routing->post('/set_password', [ SetPasswordController::CLASS, 'write' ]);
$routing->get('/forgot_password', [ ForgotPasswordController::CLASS, 'read' ])->bind($this->getPrefix().'.forgot_password');
$routing->post('/forgot_password', [ ForgotPasswordController::CLASS, 'write' ]);
$routing->get('/verify', [ RegistrationController::CLASS, 'verify' ])->bind($this->getPrefix().'.verify');
