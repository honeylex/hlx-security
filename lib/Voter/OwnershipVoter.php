<?php

namespace Hlx\Security\Voter;

use Hlx\Security\User\User;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

class OwnershipVoter extends Voter
{
    const PERMISSION_VIEW = 'PERMISSION_VIEW';
    const PERMISSION_EDIT = 'PERMISSION_EDIT';

    public function supports($attribute, $subject)
    {
        return in_array($attribute, [ self::PERMISSION_VIEW, self::PERMISSION_EDIT ]) && $subject instanceof User;
    }

    protected function voteOnAttribute($attribute, $user, TokenInterface $token)
    {
        $currentUser = $token->getUser();

        if (!$currentUser instanceof User) {
            return false;
        }

        return $user->getIdentifier() === $currentUser->getIdentifier();
    }
}
