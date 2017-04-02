<?php

namespace Hlx\Security\User;

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

    public function getPrefix()
    {
        return $this->state['@type'];
    }

    public function getIdentifier()
    {
        return $this->state['identifier'];
    }

    public function getRevision()
    {
        return $this->state['revision'];
    }

    public function getUuid()
    {
        return $this->state['uuid'];
    }

    public function getLanguage()
    {
        return $this->state['language'];
    }

    public function getVersion()
    {
        return $this->state['version'];
    }

    public function getCreatedAt()
    {
        return $this->state['created_at'];
    }

    public function getModifiedAt()
    {
        return $this->state['modified_at'];
    }

    public function getUsername()
    {
        return $this->state['username'];
    }

    public function getFirstname()
    {
        return $this->state['firstname'];
    }

    public function getLastname()
    {
        return $this->state['lastname'];
    }

    public function getPassword()
    {
        return $this->state['password_hash'];
    }

    public function getEmail()
    {
        return $this->state['email'];
    }

    public function getLocale()
    {
        return $this->state['locale'];
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

    public function getToken($type)
    {
        foreach ($this->getTokens() as $token) {
            if ($type === $token['@type']) {
                return $token;
            }
        }
    }

    public function isAccountNonLocked()
    {
        return $this->getWorkflowState() !== 'deleted';
    }

    /*
     * Login event is applied after symfony authentication so performing token
     * checks here will block valid login. UserTokenAuthenticator handles
     * checks instead. RememberMe services do not do post-auth checks,
     * so in any case this is not executed for auto-logins via cookie...
     */
    public function isCredentialsNonExpired()
    {
        return true;
    }

    /*
     * So instead we have a method for doing additional checks outside the
     * standard symfony flow...
     */
    public function isAuthenticationTokenNonExpired()
    {
        /*
         * @todo need to invalidate on token string changes as well but that should be
         * done somehow in the AbstractToken::hasUserChanged() method, which is private..
         */
        $token = $this->getToken('authentication');
        return new DateTime('now') < new DateTime($token['expires_at']);
    }

    public function isEnabled()
    {
        return $this->getWorkflowState() !== 'deactivated';
    }

    public function isVerified()
    {
        return $this->getWorkflowState() === 'verified';
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

    public function createCopyWith(array $state)
    {
        return new static(array_merge($this->state, $state));
    }
}
