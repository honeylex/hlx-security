<?php

namespace Hlx\Security\Voter;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class OwnershipVoter extends Voter
{
    public function supports($attribute, $subject)
    {
        return in_array($attribute, [ 'ROLE_OWNER' ]) && $subject instanceof Request;
    }

    protected function voteOnAttribute($attribute, $request, TokenInterface $token)
    {
        $user = $token->getUser();

        if ($user instanceof User) {
            return false;
        }

        $routeParams = $request->attributes->get('_route_params');

        return isset($routeParams['identifier'])
            ? $user->getIdentifier() === $routeParams['identifier']
            : false;
    }
}
