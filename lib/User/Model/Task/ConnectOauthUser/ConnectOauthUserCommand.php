<?php

namespace Hlx\Security\User\Model\Task\ConnectOauthUser;

use Assert\Assertion;
use Honeybee\Model\Event\AggregateRootEventInterface;
use Honeybee\Model\Task\ModifyAggregateRoot\ModifyAggregateRootCommand;

class ConnectOauthUserCommand extends ModifyAggregateRootCommand
{
    const DATE_ISO8601_WITH_MICROS = 'Y-m-d\TH:i:s.uP';

    protected $id;

    protected $service;

    protected $token;

    protected $expires_at;

    public function getEventClass()
    {
        return UserOauthTokenConnectedEvent::CLASS;
    }

    public function getAffectedAttributeNames()
    {
        return [ 'firstname', 'lastname', 'tokens' ];
    }

    public function getId()
    {
        return $this->id;
    }

    public function getService()
    {
        return $this->service;
    }

    public function getExpiresAt()
    {
        return $this->expires_at;
    }

    public function getToken()
    {
        return $this->token;
    }

    protected function guardRequiredState()
    {
        parent::guardRequiredState();

        Assertion::notEmpty($this->id);
        Assertion::string($this->service);
        Assertion::notBlank($this->service);
        Assertion::date($this->expires_at, self::DATE_ISO8601_WITH_MICROS);
        Assertion::string($this->token);
        Assertion::notBlank($this->token);
    }
}
