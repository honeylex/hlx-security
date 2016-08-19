<?php

namespace Hlx\Security\User;

use Honeybee\EnvironmentInterface;
use Honeybee\Infrastructure\Command\Metadata;
use Honeybee\Infrastructure\Command\MetadataEnricherInterface;

class AuditMetadataEnricher implements MetadataEnricherInterface
{
    protected $environment;

    public function __construct(EnvironmentInterface $environment)
    {
        $this->environment = $environment;
    }

    public function enrich(Metadata $metadata)
    {
        $user = $this->environment->getUser();

        if ($user instanceof User) {
            $metadata->setItem('user', $user->getIdentifier());
            $metadata->setItem('role', $user->getRole());
        }

        return $metadata;
    }
}
