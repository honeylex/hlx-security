<?php

namespace Foh\SystemAccount\Service;

use DateTime;
use Symfony\Component\Security\Core\User\AdvancedUserInterface;

class User implements AdvancedUserInterface
{
    protected $state;

    public function __construct(array $state)
    {
        $this->state = $state;
    }

    public function __toString()
    {
        return $this->getIdentifier();
    }

    public function getIdentifier()
    {
        return $this->state['identifier'];
    }

    public function getRevision()
    {
        return $this->state['revision'];
    }

    public function getUsername()
    {
        return $this->state['username'];
    }

    public function getPassword()
    {
        return $this->state['password_hash'];
    }

    public function getEmail()
    {
        return $this->state['email'];
    }

    public function getWorkflowState()
    {
        return $this->state['workflow_state'];
    }

    public function isAccountNonExpired()
    {
        return $this->isEnabled();
    }

    public function getRole()
    {
        return $this->state['role'];
    }

    public function getRoles()
    {
        return [ $this->getRole() ];
    }

    public function getImages()
    {
        return $this->state['images'];
    }

    public function getTokens()
    {
        return $this->state['tokens'];
    }

    public function getToken($type = 'default_token')
    {
        foreach ($this->getTokens() as $token) {
            if ($type === $token['@type']) {
                return $token;
            }
        }
    }

    public function isAccountNonLocked()
    {
        return $this->isEnabled();
    }

    public function isCredentialsNonExpired()
    {
        return new DateTime('now') < new DateTime($this->getToken()['expires_at']);
    }

    public function isEnabled()
    {
        return $this->getWorkflowState() !== 'deleted';
    }

    public function getSalt()
    {
    }

    public function eraseCredentials()
    {
    }

    public function toArray()
    {
        return $this->state;
    }
}
