<?php

namespace Hlx\Security\Authentication;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationExpiredException;
use Symfony\Component\Security\Http\RememberMe\TokenBasedRememberMeServices;

class UserTokenBasedRememberMeServices extends TokenBasedRememberMeServices
{
    protected function processAutoLoginCookie(array $cookieParts, Request $request)
    {
        $user = parent::processAutoLoginCookie($cookieParts, $request);

        if (!$user->isAuthenticationTokenNonExpired()) {
            throw new AuthenticationExpiredException;
        }

        return $user;
    }
}
