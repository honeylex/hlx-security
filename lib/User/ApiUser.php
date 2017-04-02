<?php

namespace Hlx\Security\User;

class ApiUser extends User
{
    public function isCredentialsNonExpired()
    {
        return $this->isAuthenticationTokenNonExpired();
    }
}
