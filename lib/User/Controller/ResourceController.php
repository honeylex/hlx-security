<?php

namespace Hlx\Security\User\Controller;

use Hlx\Security\Service\UserService;
use Hlx\Security\User\View\ResourceSuccessView;
use Hlx\Security\Voter\OwnershipVoter;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;

class ResourceController
{
    protected $userService;

    protected $authorizationChecker;

    public function __construct(
        UserService $userService,
        AuthorizationCheckerInterface $authorizationChecker
    ) {
        $this->userService = $userService;
        $this->authorizationChecker = $authorizationChecker;
    }

    public function read(Request $request, Application $app)
    {
        $userId = $request->get('userId');
        $user = $this->userService->loadUserByIdentifier($userId);

        if (!$this->authorizationChecker->isGranted([ OwnershipVoter::PERMISSION_VIEW, 'ROLE_ADMIN' ], $user)) {
            throw new AccessDeniedException;
        }

        $request->attributes->set('user', $user);

        return [ ResourceSuccessView::CLASS ];
    }
}
