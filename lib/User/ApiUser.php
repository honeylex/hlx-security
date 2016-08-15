<?php

namespace Hlx\Security\User;

use DateTime;

class ApiUser extends User
{
    public function isCredentialsNonExpired()
    {
        $token = $this->getToken('authentication');
        return new DateTime('now') < new DateTime($token['expires_at']);
    }
}
