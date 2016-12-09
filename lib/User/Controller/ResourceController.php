<?php

namespace Hlx\Security\User\Controller;

use Hlx\Security\Service\UserService;
use Hlx\Security\User\View\ResourceSuccessView;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;

class ResourceController
{
    protected $userService;

    public function __construct(UserService $userService)
    {
        $this->userService = $userService;
    }

    public function read(Request $request, Application $app)
    {
        $user = $this->userService->loadUserByIdentifier($request->get('userId'));
        $request->attributes->set('user', $user);

        return [ ResourceSuccessView::CLASS ];
    }
}
