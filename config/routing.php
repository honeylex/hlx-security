<?php

// everything in here will be mounted below the prefix '/foh/system_account'

use Foh\SystemAccount\Controller\IndexController;
use Foh\SystemAccount\Controller\LoginController;

require __DIR__.'/User/routing.php';

$routing->get('/', [ IndexController::CLASS, 'read' ])->bind($this->getPrefix().'.index');
$routing->get('/login', [ LoginController::CLASS, 'read' ])->bind($this->getPrefix().'.login');
$routing->get('/logout', function() {})->bind($this->getPrefix().'.logout');
$routing->method('GET|POST')->match('/login_check', function () {})->bind($this->getPrefix().'.login_check');
